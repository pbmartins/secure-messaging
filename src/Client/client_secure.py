from src.Client.cipher_utils import *
from src.Client import cc_interface as cc
from src.Client import certificates
from cryptography.exceptions import *
import os
import base64


class ClientSecure:
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

    def __init__(self, cipher_spec, private_key, public_key):
        self.cipher_spec = cipher_spec
        self.cipher_suite = ClientSecure.get_cipher_suite(cipher_spec)
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

        self.user_certificates = {}

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

    def encapsulate_secure_message(self, payload):
        # Values used in key exchange
        salt = os.urandom(16)
        self.salt_list += [salt]
        nounce = get_nounce(16, payload.encode(), 
                self.cipher_suite['sha']['size'])
        self.nounces += [nounce]

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

        return deciphered_payload

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
        # Save user certificate
        for user in resource_payload['result']:
            self.user_certificates[user['id']] = {
                'pub_key': user['rsapubkey'],
                'certificate:': user['certificate']
            }

    def cipher_message_to_user(self, payload_type, message, user_id):
        assert message['cipher_spec'] == self.cipher_spec
        assert user_id in self.user_certificates

        # Cipher payload
        aes_key = os.urandom(self.cipher_suite['aes']['key_size'])
        aes_cipher, aes_iv = generate_aes_cipher(
            aes_key, self.cipher_suite['aes']['mode'])

        encryptor = aes_cipher.encryptor()
        ciphered_message = encryptor.update(message) + encryptor.finalize()

        peer_rsa_pubkey = self.user_certificates[user_id]

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
                payload_type: ciphered_message,
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
