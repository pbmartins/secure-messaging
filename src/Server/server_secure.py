from src.Client.cipher_utils import *
from src.Server import certificates, server
from cryptography.exceptions import *
import os
import base64


class ServerSecure:
    @staticmethod
    def get_cipher_suite(cipher_spec):
        specs = cipher_spec.split('-')
        aes = specs[1].split('_')
        rsa = specs[2].split('_')
        hash = specs[3]

        cipher_suite = {
            'aes': {
                'key_size': int(aes[0][3:]),
                'mode': aes[1]
            },
            'rsa': {
                'key_size': int(rsa[0][3:]),
                'padding': rsa[1]
            },
            'sha': {
                'size': hash[3:]
            }
        }
        return cipher_suite

    def __init__(self):
        self.cipher_spec = None
        self.cipher_suite = {}
        self.number_of_hash_derivations = 1
        self.salt_list = []
        self.server_cert = server.serv.certificates.cert

        self.priv_value = None
        self.pub_value = None
        self.peer_pub_value = None
        self.peer_salt = None
        self.private_key = server.serv.certificates.priv_key
        self.public_key = server.serv.certificates.pub_key

        self.user_certificates = {}

    def uncapsulate_insecure_message(self, payload):
        self.cipher_spec = payload['cipher_spec']
        self.cipher_suite = ServerSecure.get_cipher_suite(self.cipher_spec)
        self.priv_value, self.pub_value = generate_ecdh_keypair()
        self.peer_pub_value = payload['secdata']['dhpubvalue']
        self.peer_salt = payload['secdata']['salt']

        return payload['nounce']

    def encapsulate_secure_message(self, payload, nounce):
        # Values used in key exchange
        salt = os.urandom(16)
        self.salt_list += [salt]

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
        self.number_of_hash_derivations += 1

        aes_cipher, aes_iv = generate_aes_cipher(
            aes_key, self.cipher_suite['aes']['mode'])

        encryptor = aes_cipher.encryptor()
        ciphered_payload = encryptor.update(payload) + encryptor.finalize()

        # Sign payload with CC authentication public key
        message_payload = {
            'message': ciphered_payload,
            'nounce': nounce,
            'secdata': {
                'dhpubvalue': self.pub_value,
                'salt': salt,
                'iv': aes_iv
            }
        }
        signature = rsa_sign(
            self.private_key,
            message_payload,
            self.cipher_suite['sha']['size']
        )

        # Build message
        message = {
            'type': 'secure',
            'payload': message_payload,
            'signature': signature,
            'certificate': self.server_cert,
            'cipher_spec': self.cipher_spec
        }

        return message

    def uncapsulate_secure_message(self, message):
        assert message['cipher_spec'] == self.cipher_spec

        # Verify signature and certificate validity
        assert server.serv.certificates.validate_cert(message['certificate'])
        try:
            message['certificate'].get_pubkey().to_cryptography_key().verify(
                message['signature'],
                message['payload'],
                self.cipher_suite['rsa']['padding'],
                self.cipher_suite['sha']['size']
            )
        except InvalidSignature:
            return "Invalid signature"

        # Derive AES key and decipher payload
        salt_idx = self.number_of_hash_derivations
        self.number_of_hash_derivations = 1
        self.peer_pub_value = message['payload']['secdata']['dhpubvalue']
        self.peer_salt = message['payload']['secdata']['salt']

        aes_key = derive_key_from_ecdh(
            self.priv_value,
            self.peer_pub_value,
            self.salt_list[salt_idx],
            self.peer_salt,
            self.cipher_suite['aes']['key_size'],
            self.cipher_suite['sha']['size'],
            self.number_of_hash_derivations,
        )

        aes_cipher, aes_iv = generate_aes_cipher(
            aes_key,
            self.cipher_suite['aes']['mode'],
            message['payload']['secdata']['iv']
        )

        decryptor = aes_cipher.decryptor()
        deciphered_payload = decryptor.update(message['payload']['message']) \
                             + decryptor.finalize()

        return deciphered_payload, message['payload']['nounce']
