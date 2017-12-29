from src.Client.cipher_utils import *
from src.Server import certificates, server
from src.Server.log import logger
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
        self.number_of_hash_derivations = None
        self.salt = None
        self.server_cert = certs.cert
        self.priv_value = None
        self.pub_value = None
        self.peer_pub_value = None
        self.peer_salt = None
        self.private_key = certs.priv_key
        self.public_key = certs.pub_key

        self.registry = registry
        self.certs = certs
        self.user_certificates = {}

    def uncapsulate_insecure_message(self, payload):
        logger.log(logging.DEBUG, "INSECURE MESSAGE RECEIVED: %r" % payload)

        self.uuid = payload['uuid']
        self.cipher_spec = payload['cipher_spec'] if payload['cipher_spec'] is not None \
            else self.registry.getUser(self.uuid).description['secdata']['cipher_spec']
        self.cipher_suite = get_cipher_suite(self.cipher_spec)
        self.peer_pub_value = deserialize_key(payload['secdata']['dhpubvalue'])
        self.peer_salt = base64.b64decode(payload['secdata']['salt'].encode())
        self.number_of_hash_derivations = payload['secdata']['index']

        return {'type': 'init', 'uuid': self.uuid}, payload['nounce']

    def encapsulate_secure_message(self, payload, nounce):
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

        # Sign payload with CC authentication public key
        message_payload = json.dumps({
            'message': base64.b64encode(ciphered_payload).decode(),
            'nounce': nounce,
            'secdata': {
                'dhpubvalue': serialize_key(self.pub_value),
                'salt': base64.b64encode(self.salt).decode(),
                'iv': base64.b64encode(aes_iv).decode(),
                'index': self.number_of_hash_derivations
            }
        }).encode()

        signature = None
        signature = rsa_sign(
            self.private_key,
            message_payload,
            self.cipher_suite['rsa']['sign']['server']['sha'],
            self.cipher_suite['rsa']['sign']['server']['padding']
        )

        # Build message
        message = {
            'type': 'secure',
            'payload': base64.b64encode(message_payload).decode(),
            'signature': base64.b64encode(signature).decode(),
            'certificate': serialize_certificate(self.server_cert),
            'cipher_spec': self.cipher_spec
        }

        logger.log(logging.DEBUG, "SECURE MESSAGE SENT: %r" % message)

        return message

    def uncapsulate_secure_message(self, message):
        logger.log(logging.DEBUG, "SECURE MESSAGE RECEIVED: %r" % message)

        assert message['cipher_spec'] == self.cipher_spec

        deciphered_payload = None

        # Verify signature and certificate validity
        peer_certificate = deserialize_certificate(message['certificate'])
        if not self.certs.validate_cert(peer_certificate):
            logger.log(logging.DEBUG, "Invalid certificate; "
                                      "droping message")
            deciphered_payload = {'type': 'error',
                                  'error': 'Invalid server certificate'}

        if deciphered_payload is None:
            try:
                rsa_verify(
                    peer_certificate.get_pubkey().to_cryptography_key(),
                    base64.b64decode(message['signature'].encode()),
                    base64.b64decode(message['payload'].encode()),
                    self.cipher_suite['rsa']['sign']['cc']['sha'],
                    self.cipher_suite['rsa']['sign']['cc']['padding']
                )
            except InvalidSignature:
                logger.log(logging.DEBUG, "Invalid signature; "
                                          "droping message")
                deciphered_payload = {'type': 'error',
                                      'error': 'Invalid message signature'}

        message['payload'] = json.loads(
            base64.b64decode(message['payload'].encode()))

        nounce = message['payload']['nounce']

        if deciphered_payload is None:


            # Derive AES key and decipher payload
            self.number_of_hash_derivations = \
                message['payload']['secdata']['index']

            self.peer_pub_value = deserialize_key(
                message['payload']['secdata']['dhpubvalue'])
            self.peer_salt = base64.b64decode(
                message['payload']['secdata']['salt'].encode())

            aes_key = derive_key_from_ecdh(
                self.priv_value,
                self.peer_pub_value,
                self.peer_salt,
                self.salt,
                self.cipher_suite['aes']['key_size'],
                self.cipher_suite['sha']['size'],
                self.number_of_hash_derivations,
            )

            aes_cipher, aes_iv = generate_aes_cipher(
                aes_key,
                self.cipher_suite['aes']['mode'],
                base64.b64decode(message['payload']['secdata']['iv'].encode())
            )

            deciphered_payload = message['payload']['message']

            # Decipher message, if present
            if 'message' in message['payload']:
                decryptor = aes_cipher.decryptor()
                deciphered_payload = decryptor.update(base64.b64decode(
                    message['payload']['message'].encode())) + \
                                     decryptor.finalize()
                deciphered_payload = json.loads(deciphered_payload.decode())

        return deciphered_payload, nounce
