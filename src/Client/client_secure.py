from src.Client.client_keys import *
from src.Client import cc_interface as cc
import os
import base64


class ClientSecure:
    # TODO: Verify if the user can send multiple messagens without receiving
    # TODO: an answer and how it impacts the flow of DH Key exchange
    def __init__(self, cipher_spec):
        self.cipher_spec = cipher_spec
        self.cipher_suite = {}
        self.priv_value = None
        self.pub_value = None
        self.nounces = []
        self.cc_cert = cc.get_pub_key_certificate()

        self.get_cipher_suite()

    def get_cipher_suite(self):
        specs = self.cipher_spec.split('-')
        aes = specs[1].split('_')
        rsa = specs[2].split('_')
        hash = specs[3]
        
        self.cipher_suite = {
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

    def encapsulate_insecure_message(self):
        self.priv_value, self.pub_value = generate_ecdh_keypair()
        salt = os.urandom(16)
        nounce = get_nounce(16)
        self.nounces += [nounce]

        message = {
            'type': 'insecure',
            'secdata': {
                'dhpubvalue': self.pub_value,
                'salt': salt
            },
            'nounce': nounce,
            'cipher_spec': self.cipher_spec
        }

        return message

    def encapsulate_secure_message(self, payload, peer_pub_value, peer_salt):
        # Values used in key exchange
        self.priv_value, self.pub_value = generate_ecdh_keypair()
        salt = os.urandom(16)
        nounce = get_nounce(16)
        self.nounces += [nounce]

        # Derive AES key and cipher payload
        aes_key = derive_key_from_ecdh(
            self.priv_value,
            peer_pub_value,
            salt,
            peer_salt,
            self.cipher_suite['aes']['key_size'],
            self.cipher_suite['sha']['size']
        )
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
        signature = cc.sign(message_payload)

        # Build message
        message = {
            'type': 'secure',
            'payload': message_payload,
            'signature': signature,
            'certificate': self.cc_cert,
            'cipher_spec': self.cipher_spec
        }

        return message

    def uncapsulate_secure_message(self, message):
        pass

    def cipher_message_to_user(self, message, peer_rsa_pubkey):
        # Cipher payload
        aes_key = os.urandom(self.cipher_suite['aes']['key_size'])
        aes_cipher, aes_iv = generate_aes_cipher(
            aes_key, self.cipher_suite['aes']['mode'])

        encryptor = aes_cipher.encryptor()
        ciphered_message = encryptor.update(message) + encryptor.finalize()

        # Cipher AES key and IV
        aes_iv_key = aes_iv + aes_key
        ciphered_aes_iv_key = rsa_cipher(peer_rsa_pubkey, aes_iv_key,
                                         self.cipher_suite['sha']['size'],
                                         self.cipher_suite['rsa']['padding'])

        # Generate nounce to verify message readings
        nounce = get_nounce(16)
        payload = nounce + b'\n\t' + base64.b64encode(self.cipher_spec) \
                  + b'\n\t' + ciphered_aes_iv_key + b'\n\t' + ciphered_message

        # Sign payload
        signature = cc.sign(payload)
        payload += b'\n\t\n\t' + signature

        return payload

    def decipher_message_from_user(self, message, peer_rsa_pubkey):
        pass