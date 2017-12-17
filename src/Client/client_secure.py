from src.Client.client_keys import *
from src.Client import cc_interface as cc
from src.Client import certificates
from cryptography.exceptions import *
import os
import base64


class ClientSecure:
    def __init__(self, cipher_spec, private_key, public_key):
        self.cipher_spec = cipher_spec
        self.cipher_suite = {}
        self.number_of_hash_derivations = 1
        self.salt_list = []
        self.nounces = []
        self.cc_cert = cc.get_pub_key_certificate()
        self.certificates = certificates.X509Certificates()

        self.priv_value, self.pub_value = generate_ecdh_keypair()
        self.private_key = private_key
        self.public_key = public_key

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
        nounce = get_nounce(16, b'', self.cipher_suite['sha']['size'])
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
        salt = os.urandom(16)
        self.salt_list += [salt]
        nounce = get_nounce(16, payload.encode(), 
                self.cipher_suite['sha']['size'])
        self.nounces += [nounce]

        # Derive AES key and cipher payload
        aes_key = derive_key_from_ecdh(
            self.priv_value,
            peer_pub_value,
            salt,
            peer_salt,
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
        assert message['cipher_spec'] == self.cipher_spec

        # Verify signature and certificate validity
        assert self.certificates.validate_cert(message['certificate'])
        try:
            message['certificate'].get_pubkey().to_cryptography_key().verify(
                message['signature'],
                message['payload'],
                self.cipher_suite['rsa']['padding'],
                self.cipher_suite['sha']['size']
            )
        except InvalidSignature:
            return "Invalid signature"

        # Check if it corresponds to a previously sent message
        if not message['payload']['nounce'] in self.nounces:
            return "Message not a response to a previously sent message"

        self.nounces.remove(message['payload']['nounce'])

        # Derive AES key and decipher payload
        salt_idx = self.number_of_hash_derivations
        self.number_of_hash_derivations = 1

        aes_key = derive_key_from_ecdh(
            self.priv_value,
            message['payload']['secdata']['dhpubvalue'],
            self.salt_list[salt_idx],
            message['payload']['secdata']['salt'],
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

        return deciphered_payload

    def cipher_message_to_user(self, message, peer_rsa_pubkey):
        # Cipher payload
        aes_key = os.urandom(self.cipher_suite['aes']['key_size'])
        aes_cipher, aes_iv = generate_aes_cipher(
            aes_key, self.cipher_suite['aes']['mode'])

        encryptor = aes_cipher.encryptor()
        ciphered_message = encryptor.update(message) + encryptor.finalize()

        # Cipher AES key and IV
        aes_iv_key = aes_iv + aes_key
        ciphered_aes_iv_key = rsa_cipher(
            peer_rsa_pubkey,
            aes_iv_key,
            self.cipher_suite['sha']['size'],
            self.cipher_suite['rsa']['padding']
        )

        # Generate nounce to verify message readings
        nounce = get_nounce(16, message.encode(), 
                self.cipher_suite['sha']['size'])
        payload = {
            'payload': {
                'message': ciphered_message,
                'nounce': nounce,
                'key_iv': ciphered_aes_iv_key
            },
            'signature': None,
            'cipher_spec': self.cipher_spec
        }

        # Sign payload
        signature = cc.sign(payload['payload'])
        payload['signature'] = signature

        return payload

    def decipher_message_from_user(self, payload, peer_certificate):
        assert payload['cipher_spec'] == self.cipher_spec

        # Verify signature and certificate validity
        assert self.certificates.validate_cert(peer_certificate)
        try:
            peer_certificate.get_pubkey().to_cryptography_key().verify(
                payload['signature'],
                payload['payload'],
                self.cipher_suite['rsa']['padding'],
                self.cipher_suite['sha']['size']
            )
        except InvalidSignature:
            return "Invalid signature"

        # Decipher AES key and IV
        aes_iv_key = rsa_decipher(
            self.private_key,
            payload['payload']['key_iv'],
            self.cipher_suite['sha']['size'],
            self.cipher_suite['rsa']['padding']
        )
        aes_iv = aes_iv_key[:16]
        aes_key = aes_iv_key[16:]

        # Decipher payload
        aes_cipher, aes_iv = generate_aes_cipher(
            aes_key, self.cipher_suite['aes']['mode'], aes_iv)

        decryptor = aes_cipher.decryptor()
        deciphered_message = decryptor.update(payload['payload']['message']) \
                             + decryptor.finalize()

        return deciphered_message
