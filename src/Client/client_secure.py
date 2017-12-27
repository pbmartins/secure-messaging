from src.Client.cipher_utils import *
from src.Client import cc_interface as cc
from src.Client import certificates
from src.Client.log import logger
from cryptography.exceptions import *
from OpenSSL import crypto
import os
import base64
import json
import logging


class ClientSecure:

    def __init__(self, uuid, private_key, public_key, cipher_spec=None, cipher_suite=None, pin=None):
        self.uuid = uuid
        self.cipher_spec = cipher_spec
        self.cipher_suite = cipher_suite
        self.number_of_hash_derivations = 1
        self.salt_list = []
        self.nounces = []
        self.cc_cert = cc.get_pub_key_certificate()
        self.certificates = certificates.X509Certificates()

        self.priv_value = None
        self.pub_value = None
        self.peer_pub_value = None
        self.peer_salt = None
        self.private_key = private_key
        self.public_key = public_key

        self.cc_pin = pin

        self.user_certificates = {}

    def encapsulate_insecure_message(self):
        self.priv_value, self.pub_value = generate_ecdh_keypair()
        salt = os.urandom(16)
        self.salt_list += [salt]
        nounce = self.uuid
        self.nounces += [nounce]

        message = {
            'type': 'insecure',
            'uuid': self.uuid,
            'secdata': {
                'dhpubvalue': serialize_key(self.pub_value),
                'salt': base64.b64encode(salt).decode(),
                'index': self.number_of_hash_derivations
            },
            'nounce': nounce,
            'cipher_spec': self.cipher_spec
        }
        logger.log(logging.DEBUG, "INSECURE MESSAGE SENT: %r" % message)

        return message

    def encapsulate_secure_message(self, payload):
        # Values used in key exchange
        salt = os.urandom(16)
        self.salt_list += [salt]
        nounce = base64.b64encode(get_nounce(16, json.dumps(payload).encode(),
                self.cipher_suite['sha']['size'])).decode()
        self.nounces += [nounce]
        self.number_of_hash_derivations += 1

        # Derive AES key and cipher payload
        aes_key = derive_key_from_ecdh(
            self.priv_value,
            self.peer_pub_value,
            salt,
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
                'salt': base64.b64encode(salt).decode(),
                'iv': base64.b64encode(aes_iv).decode(),
                'index': self.number_of_hash_derivations
            }
        }).encode()

        signature = cc.sign(message_payload, self.cc_pin)

        # Build message
        message = {
            'type': 'secure',
            'payload': base64.b64encode(message_payload).decode(),
            'signature': base64.b64encode(signature).decode(),
            'certificate': serialize_certificate(self.cc_cert),
            'cipher_spec': self.cipher_spec
        }

        logger.log(logging.DEBUG, "SECURE MESSAGE SENT: %r" % message)

        return message

    def uncapsulate_secure_message(self, message):
        if self.cipher_spec is None:
            self.cipher_spec = message['cipher_spec']
            self.cipher_suite = get_cipher_suite(self.cipher_spec)

        assert message['cipher_spec'] == self.cipher_spec

        # Verify signature and certificate validity
        peer_certificate = deserialize_certificate(message['certificate'])
        if not self.certificates.validate_cert(peer_certificate):
            print("Invalid certificate")
        try:
            rsa_verify(
                peer_certificate.get_pubkey().to_cryptography_key(),
                base64.b64decode(message['signature'].encode()),
                base64.b64decode(message['payload'].encode()),
                self.cipher_suite['rsa']['sign']['server']['sha'],
                self.cipher_suite['rsa']['sign']['server']['padding']
            )
        except InvalidSignature:
            return "Invalid signature"

        message['payload'] = json.loads(
            base64.b64decode(message['payload'].encode()))

        logger.log(logging.DEBUG, "SECURE MESSAGE RECEIVED: %r" % message)

        # Check if it corresponds to a previously sent message
        if not message['payload']['nounce'] in self.nounces:
            return "Message not a response to a previously sent message"

        self.nounces.remove(message['payload']['nounce'])

        # Derive AES key and decipher payload
        salt_idx = self.number_of_hash_derivations - 1
        self.peer_pub_value = deserialize_key(
            message['payload']['secdata']['dhpubvalue'])
        self.peer_salt = base64.b64decode(
            message['payload']['secdata']['salt'].encode())

        aes_key = derive_key_from_ecdh(
            self.priv_value,
            self.peer_pub_value,
            self.peer_salt,
            self.salt_list[salt_idx],
            self.cipher_suite['aes']['key_size'],
            self.cipher_suite['sha']['size'],
            self.number_of_hash_derivations,
        )

        aes_cipher, aes_iv = generate_aes_cipher(
            aes_key,
            self.cipher_suite['aes']['mode'],
            base64.b64decode(message['payload']['secdata']['iv'].encode())
        )

        decryptor = aes_cipher.decryptor()
        deciphered_payload = decryptor.update(base64.b64decode(
            message['payload']['message'].encode())) + decryptor.finalize()
        deciphered_payload = json.loads(json.loads(deciphered_payload.decode()))

        # Derive new DH values
        self.priv_value, self.pub_value = generate_ecdh_keypair()
        self.number_of_hash_derivations = 0
        self.salt_list = []

        return deciphered_payload, message['payload']['nounce']

    def encapsulate_resource_message(self, ids):
        # Check if already exists user public infos
        for user in ids:
            if user in self.user_certificates:
                ids.remove(user)

        if not len(ids):
            return None

        # Construct resource payload
        resource_payload = {
            'type': 'resource',
            'ids': ids
        }

        return resource_payload

    def uncapsulate_resource_message(self, resource_payload):
        # Save user public values, certificate and cipher_spec
        for user in resource_payload['result']:
            self.user_certificates[user['id']] = {
                'pub_key': deserialize_key(user['rsapubkey']),
                'cc_pub_key': deserialize_key(user['ccpubkey']),
                'certificate:': deserialize_certificate(user['cccertificate']),
                'cipher_spec': get_cipher_suite(user['cipher_spec'])
            }

    def cipher_message_to_user(self, payload_type, message, user_id, peer_rsa_pubkey=None):
        # Cipher payload
        aes_key = os.urandom(self.cipher_suite['aes']['key_size'])
        aes_cipher, aes_iv = generate_aes_cipher(
            aes_key, self.cipher_suite['aes']['mode'])

        encryptor = aes_cipher.encryptor()
        ciphered_message = encryptor.update(json.dumps(message).encode()) + \
                           encryptor.finalize()

        if peer_rsa_pubkey is None:
            peer_rsa_pubkey = self.user_certificates[user_id]['pub_key']

        # Cipher AES key and IV
        aes_iv_key = aes_iv + aes_key
        ciphered_aes_iv_key = rsa_cipher(
            peer_rsa_pubkey,
            aes_iv_key,
            self.cipher_suite['sha']['size'],
            self.cipher_suite['rsa']['cipher']['padding']
        )

        # Generate nounce to verify message readings
        nounce = base64.b64encode(get_nounce(16, message.encode(),
                self.cipher_suite['sha']['size'])).decode()

        payload = {
            'payload': {
                payload_type: base64.b64encode(ciphered_message).decode(),
                'nounce': nounce,
                'key_iv': base64.b64encode(ciphered_aes_iv_key).decode()
            },
            'signature': None,
            'cipher_spec': self.cipher_spec
        }

        # Sign payload
        #payload['signature'] = cc.sign(payload['payload'], self.cc_pin)

        return base64.b64encode(json.dumps(payload).encode()).decode()

    def decipher_message_from_user(self, payload, peer_certificate):
        """
        # Verify signature and certificate validity
        peer_certificate = deserialize_certificate(peer_certificate)
        assert self.certificates.validate_cert(peer_certificate)
        try:
            rsa_verify(
                peer_certificate.get_pubkey().to_cryptography_key(),
                base64.b64decode(payload['signature'].encode()),
                base64.b64decode(payload['payload'].encode()),
                self.cipher_suite['sha']['sign']['cc']['sha'],
                self.cipher_suite['rsa']['sign']['cc']['padding']
            )
        except InvalidSignature:
            return "Invalid signature"
        """
        # Decode payload
        payload = json.loads(base64.b64decode(payload))

        # Decipher AES key and IV
        aes_iv_key = rsa_decipher(
            self.private_key,
            base64.b64decode(payload['payload']['key_iv'].encode()),
            self.cipher_suite['sha']['size'],
            self.cipher_suite['rsa']['cipher']['padding']
        )
        aes_iv = aes_iv_key[:16]
        aes_key = aes_iv_key[16:]

        # Decipher payload
        aes_cipher, aes_iv = generate_aes_cipher(
            aes_key, self.cipher_suite['aes']['mode'], aes_iv)

        decryptor = aes_cipher.decryptor()
        deciphered_message = decryptor.update(base64.b64decode(
            payload['payload']['message'].encode())) + decryptor.finalize()

        return deciphered_message.decode()
