from src.Client.cipher_utils import *
from src.Client import cc_interface as cc
from src.Client import certificates, log
from cryptography.exceptions import *
from OpenSSL import crypto
import os
import base64
import json
import logging


class ClientSecure:
    @staticmethod
    def get_cipher_suite(cipher_spec):
        specs = cipher_spec.split('-')
        aes = specs[1].split('_')
        rsa = specs[2].split('_')
        hash = specs[3]

        cipher_suite = {
            'aes': {
                'key_size': int(aes[0][3:]) // 8,
                'mode': aes[1]
            },
            'rsa': {
                'key_size': int(rsa[0][3:]),
                'padding': rsa[1]
            },
            'sha': {
                'size': int(hash[3:])
            }
        }
        return cipher_suite

    @staticmethod
    def serialize_key(pub_value):
        return base64.b64encode(pub_value.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)).decode()

    @staticmethod
    def deserialize_key(pub_value):
        return serialization.load_pem_public_key(base64.b64decode(
            pub_value.encode()), default_backend())

    @staticmethod
    def serialize_certificate(cert):
        return base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_PEM, cert)).decode()

    @staticmethod
    def deserialize_certificate(cert):
        return crypto.load_certificate(crypto.FILETYPE_PEM, base64.b64decode(cert.encode()))

    def __init__(self, uuid, private_key, public_key, cipher_spec=None, cipher_suite=None):
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
                'dhpubvalue': ClientSecure.serialize_key(self.pub_value),
                'salt': base64.b64encode(salt).decode(),
                'index': self.number_of_hash_derivations
            },
            'nounce': nounce,
            'cipher_spec': self.cipher_spec
        }
        log.log(logging.DEBUG, "INSECURE MESSAGE SENT: %r" % message)

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
                'dhpubvalue': ClientSecure.serialize_key(self.pub_value),
                'salt': base64.b64encode(salt).decode(),
                'iv': base64.b64encode(aes_iv).decode(),
                'index': self.number_of_hash_derivations
            }
        }).encode()

        signature = None
        #signature = cc.sign(message_payload)

        # Build message
        message = {
            'type': 'secure',
            'payload': base64.b64encode(message_payload).decode(),
            'signature': signature,
            'certificate': ClientSecure.serialize_certificate(self.cc_cert),
            'cipher_spec': self.cipher_spec
        }

        log.log(logging.DEBUG, "SECURE MESSAGE SENT: %r" % message)

        return message

    def uncapsulate_secure_message(self, message):
        print(self.cipher_spec)
        if self.cipher_spec is None:
            self.cipher_spec = message['cipher_spec']
            self.cipher_suite = ClientSecure.get_cipher_suite(self.cipher_spec)

        print(self.cipher_spec)
        assert message['cipher_spec'] == self.cipher_spec
        """
        # Verify signature and certificate validity
        peer_certificate = ClientSecure.deserialize_certificate(message['certificate'])
        assert self.certificates.validate_cert(peer_certificate)
        try:
            peer_certificate.get_pubkey().to_cryptography_key().verify(
                message['signature'],
                base64.b64decode(message['payload'].encode()),
                self.cipher_suite['rsa']['padding'],
                self.cipher_suite['sha']['size']
            )
        except InvalidSignature:
            return "Invalid signature"
        """

        message['payload'] = json.loads(
            base64.b64decode(message['payload'].encode()))

        log.log(logging.DEBUG, "SECURE MESSAGE RECEIVED: %r" % message)

        # Check if it corresponds to a previously sent message
        if not message['payload']['nounce'] in self.nounces:
            return "Message not a response to a previously sent message"

        self.nounces.remove(message['payload']['nounce'])

        # Derive AES key and decipher payload
        salt_idx = self.number_of_hash_derivations - 1
        self.peer_pub_value = ClientSecure.deserialize_key(
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
        # Save user public values, certificate and cipher_spec
        for user in resource_payload['result']:
            self.user_certificates[user['id']] = {
                'pub_key': ClientSecure.deserialize_key(user['rsapubkey']),
                'cc_pub_key': ClientSecure.deserialize_key(user['ccpubkey']),
                'certificate:': ClientSecure.deserialize_certificate(user['cccertificate']),
                'cipher_spec': ClientSecure.get_cipher_suite(user['cipher_spec'])
            }

    def cipher_message_to_user(self, payload_type, message, user_id):
        # TODO: this assert is really needed?
        #assert message['cipher_spec'] == self.cipher_spec
        assert user_id in self.user_certificates

        # Cipher payload
        aes_key = os.urandom(self.cipher_suite['aes']['key_size'])
        aes_cipher, aes_iv = generate_aes_cipher(
            aes_key, self.cipher_suite['aes']['mode'])

        encryptor = aes_cipher.encryptor()
        ciphered_message = encryptor.update(json.dumps(message).encode()) + \
                           encryptor.finalize()

        peer_rsa_pubkey = self.user_certificates[user_id]['pub_key']

        # Cipher AES key and IV
        aes_iv_key = aes_iv + aes_key
        ciphered_aes_iv_key = rsa_cipher(
            peer_rsa_pubkey,
            aes_iv_key,
            self.cipher_suite['sha']['size'],
            self.cipher_suite['rsa']['padding']
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
        #signature = cc.sign(payload['payload'])
        #payload['signature'] = signature

        return base64.b64encode(json.dumps(payload).encode()).decode()

    def decipher_message_from_user(self, payload, peer_certificate):
        # TODO: this assert is really needed?
        #assert payload['cipher_spec'] == self.cipher_spec
        """
        # Verify signature and certificate validity
        peer_certificate = ClientSecure.deserialize_certificate(peer_certificate)
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
        """

        # Decode payload
        payload = json.loads(base64.b64decode(payload))

        # Decipher AES key and IV
        aes_iv_key = rsa_decipher(
            self.private_key,
            base64.b64decode(payload['payload']['key_iv'].encode()),
            self.cipher_suite['sha']['size'],
            self.cipher_suite['rsa']['padding']
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
