from cipher_utils import *
from log import logger
from cryptography.exceptions import *
from OpenSSL import crypto
import os
import base64
import json
import logging


class ServerSecure:

    def __init__(self, registry, certs):
        self.uuid = None
        self.cipher_spec = None
        self.cipher_suite = {}

        self.salt = None
        self.server_cert = certs.cert
        self.priv_value = None
        self.pub_value = None
        self.peer_pub_value = None
        self.peer_salt = None
        self.number_of_hash_derivations = None
        self.prev_mac = None

        self.private_key = certs.priv_key
        self.public_key = certs.pub_key

        self.registry = registry
        self.certs = certs

    def uncapsulate_init_message(self, payload):
        logger.log(logging.DEBUG, "INIT MESSAGE RECEIVED: %r" % payload)

        # Check all payload fields
        if 'payload' not in payload or 'cipher_spec' not in payload \
            or 'signature' not in payload or 'certificate' not in payload:
            logger.log(logging.DEBUG, "ERROR: INCOMPLETE FIELDS IN INIT "
                                      "MESSAGE: %r" % payload)
            return

        sent_payload = json.loads(base64.b64decode(
            payload['payload'].encode()).decode())

        self.uuid = sent_payload['uuid']
        self.cipher_spec = payload['cipher_spec'] \
            if payload['cipher_spec'] is not None \
            else json.loads(base64.b64decode(self.registry.getUser(
            self.uuid).description['secdata'].encode()).decode())['cipher_spec']
        self.cipher_suite = get_cipher_suite(self.cipher_spec)

        deciphered_payload = None

        # Verify signature and certificate validity to authenticate client
        peer_certificate = deserialize_certificate(payload['certificate'])
        if not self.certs.validate_cert(peer_certificate):
            logger.log(logging.DEBUG, "Invalid certificate; "
                                      "dropping message")
            deciphered_payload = {'type': 'error',
                                  'error': 'Invalid server certificate'}

        if deciphered_payload is None:
            try:
                rsa_verify(
                    peer_certificate.get_pubkey().to_cryptography_key(),
                    base64.b64decode(payload['signature'].encode()),
                    payload['payload'].encode(),
                    self.cipher_suite['rsa']['sign']['cc']['sha'],
                    self.cipher_suite['rsa']['sign']['cc']['padding']
                )
            except InvalidSignature:
                logger.log(logging.DEBUG, "Invalid signature; "
                                          "dropping message")
                deciphered_payload = {'type': 'error',
                                      'error': 'Invalid message signature'}

        if deciphered_payload is None:
            self.peer_pub_value = deserialize_key(
                sent_payload['secdata']['dhpubvalue'])
            self.peer_salt = base64.b64decode(
                sent_payload['secdata']['salt'].encode())
            self.number_of_hash_derivations = sent_payload['secdata']['index']
        else:
            self.uuid = None
            self.cipher_spec = None
            self.cipher_suite = None

        return {'type': 'init', 'uuid': self.uuid}, sent_payload['nonce']

    def encapsulate_secure_message(self, payload, nonce):
        # Values used in key exchange
        self.salt = os.urandom(16)
        self.priv_value, self.pub_value = generate_ecdh_keypair()

        # Derive AES key and cipher payload
        aes_key = derive_key_from_ecdh(
            self.priv_value,
            self.peer_pub_value,
            self.salt,
            self.peer_salt,
            self.cipher_suite['aes']['key_size'],
            self.cipher_suite['sha']['size'],
            self.number_of_hash_derivations,
        )

        aes_cipher, aes_iv = generate_aes_cipher(
            aes_key, self.cipher_suite['aes']['mode'])

        encryptor = aes_cipher.encryptor()
        ciphered_payload = encryptor.update(json.dumps(payload).encode())\
                           + encryptor.finalize()

        message_payload = base64.b64encode(json.dumps({
            'message': base64.b64encode(ciphered_payload).decode(),
            'nonce': nonce,
            'secdata': {
                'dhpubvalue': serialize_key(self.pub_value),
                'salt': base64.b64encode(self.salt).decode(),
                'iv': base64.b64encode(aes_iv).decode(),
                'index': self.number_of_hash_derivations
            }
        }).encode())

        mac = None

        if self.prev_mac is None:
            # Sign payload with Server authentication public key
            signature = rsa_sign(
                self.private_key,
                message_payload,
                self.cipher_suite['rsa']['sign']['server']['sha'],
                self.cipher_suite['rsa']['sign']['server']['padding']
            )

            # Generate MAC
            mac = base64.b64encode(generate_mac(
                aes_key, message_payload, self.cipher_suite['sha']['size']))

            # Build message
            message = {
                'type': 'secure',
                'payload': message_payload.decode(),
                'mac': mac.decode(),
                'signature': base64.b64encode(signature).decode(),
                'certificate': serialize_certificate(self.server_cert),
                'cipher_spec': self.cipher_spec
            }
        else:
            # Generate MAC
            mac = base64.b64encode(generate_mac(
                aes_key,
                message_payload + self.prev_mac,
                self.cipher_suite['sha']['size']
            ))

            # Build message
            message = {
                'type': 'secure',
                'payload': message_payload.decode(),
                'mac': mac.decode(),
                'cipher_spec': self.cipher_spec
            }

        self.prev_mac = mac

        logger.log(logging.DEBUG, "SECURE MESSAGE SENT: %r" % message)

        return message

    def uncapsulate_secure_message(self, message):
        logger.log(logging.DEBUG, "SECURE MESSAGE RECEIVED: %r" % message)

        assert message['cipher_spec'] == self.cipher_spec

        # Check all payload fields
        if 'payload' not in message or 'cipher_spec' not in message \
                or 'mac' not in message:
            logger.log(logging.DEBUG, "ERROR: INCOMPLETE FIELDS IN SECURE "
                                      "MESSAGE: %r" % message)
            return

        return_payload = None
        aes_key = None

        payload = json.loads(base64.b64decode(
            message['payload'].encode()).decode())

        nonce = payload['nonce']

        if return_payload is None:
            # Derive AES key and decipher payload
            self.number_of_hash_derivations = payload['secdata']['index']

            self.peer_pub_value = deserialize_key(
                payload['secdata']['dhpubvalue'])
            self.peer_salt = base64.b64decode(
                payload['secdata']['salt'].encode())

            aes_key = derive_key_from_ecdh(
                self.priv_value,
                self.peer_pub_value,
                self.peer_salt,
                self.salt,
                self.cipher_suite['aes']['key_size'],
                self.cipher_suite['sha']['size'],
                self.number_of_hash_derivations,
            )

            # Verify MAC to make sure of message integrity
            if not verify_mac(aes_key, message['payload'].encode() + self.prev_mac,
                              base64.b64decode(message['mac'].encode()),
                              self.cipher_suite['sha']['size']):
                return_payload = \
                    {'type': 'error', 'error': "Invalid MAC; dropping message"}

        if return_payload is None:
            self.prev_mac = message['mac'].encode()

            # Decipher payload
            aes_cipher, aes_iv = generate_aes_cipher(
                aes_key,
                self.cipher_suite['aes']['mode'],
                base64.b64decode(payload['secdata']['iv'].encode())
            )

            return_payload = payload['message']

            # Decipher message, if present
            if 'message' in payload:
                decryptor = aes_cipher.decryptor()
                return_payload = decryptor.update(base64.b64decode(
                    payload['message'].encode())) + decryptor.finalize()
                return_payload = json.loads(return_payload.decode())

        return return_payload, nonce
