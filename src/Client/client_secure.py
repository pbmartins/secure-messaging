from log import logger
from cipher_utils import *
import cc_interface as cc
import certificates
from cryptography.exceptions import *
import os
import base64
import json
import logging
import time


class ClientSecure:

    def __init__(self, uuid, private_key, public_key, cipher_spec=None,
                 cipher_suite=None, pin=None):
        self.uuid = uuid
        self.cipher_spec = cipher_spec
        self.cipher_suite = cipher_suite
        self.number_of_hash_derivations = 1
        self.salt_list = []
        self.nonces = []
        self.cc_cert = cc.get_pub_key_certificate()
        self.certificates = certificates.X509Certificates()

        self.priv_value = None
        self.pub_value = None
        self.peer_pub_value = None
        self.peer_salt = None
        self.private_key = private_key
        self.public_key = public_key

        self.cc_pin = pin

        self.user_resources = {}

    def cc_sign_json(self, payload):
        return base64.b64encode(cc.sign(
            json.dumps(payload).encode(), self.cc_pin)).decode()

    def encapsulate_insecure_message(self):
        self.priv_value, self.pub_value = generate_ecdh_keypair()
        salt = os.urandom(16)
        self.salt_list += [salt]
        nonce = base64.b64encode(os.urandom(16)).decode()
        self.nonces += [nonce]

        message = {
            'type': 'insecure',
            'uuid': self.uuid,
            'secdata': {
                'dhpubvalue': serialize_key(self.pub_value),
                'salt': base64.b64encode(salt).decode(),
                'index': self.number_of_hash_derivations
            },
            'nonce': nonce,
            'cipher_spec': self.cipher_spec
        }
        logger.log(logging.DEBUG, "INSECURE MESSAGE SENT: %r" % message)

        return message

    def encapsulate_secure_message(self, payload):
        # Values used in key exchange
        salt = os.urandom(16)
        self.salt_list += [salt]
        nonce = base64.b64encode(get_nonce(16, json.dumps(payload).encode(),
                self.cipher_suite['sha']['size'])).decode()
        self.nonces += [nonce]
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
        message_payload = {
            'message': base64.b64encode(ciphered_payload).decode(),
            'nonce': nonce,
            'secdata': {
                'dhpubvalue': serialize_key(self.pub_value),
                'salt': base64.b64encode(salt).decode(),
                'iv': base64.b64encode(aes_iv).decode(),
                'index': self.number_of_hash_derivations
            }
        }

        signature = self.cc_sign_json(message_payload)
        sent_payload = base64.b64encode(
            json.dumps(message_payload).encode()).decode()

        # Build message
        message = {
            'type': 'secure',
            'payload': sent_payload,
            'signature': signature,
            'certificate': serialize_certificate(self.cc_cert),
            'cipher_spec': self.cipher_spec
        }

        logger.log(logging.DEBUG, "SECURE MESSAGE SENT: %r" % message)

        return message

    def uncapsulate_secure_message(self, message):
        logger.log(logging.DEBUG, "SECURE MESSAGE RECEIVED: %r" % message)

        if self.cipher_spec is None:
            self.cipher_spec = message['cipher_spec']
            self.cipher_suite = get_cipher_suite(self.cipher_spec)

        assert message['cipher_spec'] == self.cipher_spec

        deciphered_payload = None

        # Verify signature and certificate validity
        peer_certificate = deserialize_certificate(message['certificate'])
        if not self.certificates.validate_cert(peer_certificate):
            logger.log(logging.DEBUG, "Invalid certificate; "
                                      "droping message")
            deciphered_payload = {'error': 'Invalid server certificate'}

        if deciphered_payload is None:
            try:
                rsa_verify(
                    peer_certificate.get_pubkey().to_cryptography_key(),
                    base64.b64decode(message['signature'].encode()),
                    base64.b64decode(message['payload'].encode()),
                    self.cipher_suite['rsa']['sign']['server']['sha'],
                    self.cipher_suite['rsa']['sign']['server']['padding']
                )
            except InvalidSignature:
                logger.log(logging.DEBUG, "Invalid signature; "
                                          "droping message")
                deciphered_payload = {'error': 'Invalid message signature'}

        if deciphered_payload is None:
            message['payload'] = json.loads(
                base64.b64decode(message['payload'].encode()))

            # Check if it corresponds to a previously sent message
            if not message['payload']['nonce'] in self.nonces:
                deciphered_payload = \
                    {'error': "Message doesn't match a previously sent message"}

        if deciphered_payload is None:
            self.nonces.remove(message['payload']['nonce'])

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
            deciphered_payload = \
                json.loads(json.loads(deciphered_payload.decode()))

        # Derive new DH values
        self.priv_value, self.pub_value = generate_ecdh_keypair()
        self.number_of_hash_derivations = 0
        self.salt_list = []

        return deciphered_payload

    def encapsulate_resource_message(self, ids):
        # Check if already exists user public infos
        for user in ids:
            if user in self.user_resources:
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
            # Verify signature and certificate validity
            cipher_suite = get_cipher_suite(user['secdata']['cipher_spec'])

            user_cert = deserialize_certificate(user['secdata']['cccertificate'])
            if not self.certificates.validate_cert(user_cert):
                logger.log(logging.DEBUG, "Invalid certificate; "
                                          "dropping user info")
                continue

            try:
                rsa_verify(
                    user_cert.get_pubkey().to_cryptography_key(),
                    base64.b64decode(user['signature'].encode()),
                    json.dumps(user['secdata']).encode(),
                    cipher_suite['rsa']['sign']['cc']['sha'],
                    cipher_suite['rsa']['sign']['cc']['padding']
                )
            except InvalidSignature:
                logger.log(logging.DEBUG, "Invalid signature; "
                                          "dropping user info")
                continue

            self.user_resources[user['id']] = {
                'pub_key': deserialize_key(user['secdata']['rsapubkey']),
                'cc_pub_key': user_cert.get_pubkey().to_cryptography_key(),
                'certificate': user_cert,
                'cipher_suite': cipher_suite
            }

    def cipher_message_to_user(self, message, peer_rsa_pubkey=None, nonce=None,
                               cipher_suite=None):

        if cipher_suite is None:
            cipher_suite = self.cipher_suite

        # Cipher payload
        aes_key = os.urandom(cipher_suite['aes']['key_size'])
        aes_cipher, aes_iv = generate_aes_cipher(
            aes_key, cipher_suite['aes']['mode'])

        encryptor = aes_cipher.encryptor()
        ciphered_message = encryptor.update(json.dumps(message).encode()) + \
                           encryptor.finalize()

        if peer_rsa_pubkey is None:
            peer_rsa_pubkey = self.public_key

        # Generate nonce to verify message readings
        if nonce is None:
            nonce = get_nonce(16, message.encode(),
                                cipher_suite['sha']['size'])

        # Cipher nonce and AES key and IV
        nonce_aes_iv_key = aes_iv + aes_key + nonce
        ciphered_nonce_aes_iv_key = rsa_cipher(
            peer_rsa_pubkey,
            nonce_aes_iv_key,
            cipher_suite['sha']['size'],
            cipher_suite['rsa']['cipher']['padding']
        )

        payload = {
            'payload': {
                'message': base64.b64encode(ciphered_message).decode(),
                'nonce_key_iv':
                    base64.b64encode(ciphered_nonce_aes_iv_key).decode()
            },
            'signature': None,
            'cipher_spec': cipher_suite
        }

        # Sign payload
        payload['signature'] = base64.b64encode(cc.sign(
            json.dumps(payload['payload']).encode(), self.cc_pin)).decode()

        return base64.b64encode(json.dumps(payload).encode()).decode(), nonce

    def decipher_message_from_user(self, payload, peer_certificate=None):
        deciphered_message = None

        if peer_certificate is None:
            peer_certificate = self.cc_cert

        # Verify signature and certificate validity
        if not self.certificates.validate_cert(peer_certificate):
            logger.log(logging.DEBUG, "Invalid certificate; "
                                      "droping message")
            deciphered_message = {'error': 'Invalid peer certificate'}

        # Decode payload
        payload = json.loads(base64.b64decode(payload))

        cipher_suite = payload['cipher_spec']

        if deciphered_message is None:
            try:
                rsa_verify(
                    peer_certificate.get_pubkey().to_cryptography_key(),
                    base64.b64decode(payload['signature']),
                    json.dumps(payload['payload']).encode(),
                    cipher_suite['rsa']['sign']['cc']['sha'],
                    cipher_suite['rsa']['sign']['cc']['padding']
                )
            except InvalidSignature:
                logger.log(logging.DEBUG, "Invalid signature; "
                                          "droping message")
                deciphered_message = {'error': 'Invalid message signature'}

        nonce = None
        if deciphered_message is None:
            # Decipher nonce and AES key and IV
            nonce_aes_iv_key = rsa_decipher(
                self.private_key,
                base64.b64decode(payload['payload']['nonce_key_iv'].encode()),
                cipher_suite['sha']['size'],
                cipher_suite['rsa']['cipher']['padding']
            )

            # If the user can't decrypt, return error message
            if isinstance(nonce_aes_iv_key, dict) \
                    and 'error' in nonce_aes_iv_key:
                return nonce_aes_iv_key, nonce, cipher_suite

            aes_iv = nonce_aes_iv_key[0:16]
            aes_key = nonce_aes_iv_key[16:16+cipher_suite['aes']['key_size']]
            nonce = nonce_aes_iv_key[16+cipher_suite['aes']['key_size']:]

            # Decipher payload
            aes_cipher, aes_iv = generate_aes_cipher(
                aes_key, cipher_suite['aes']['mode'], aes_iv)

            decryptor = aes_cipher.decryptor()
            deciphered_message = decryptor.update(
                base64.b64decode(payload['payload']['message'].encode()))\
                                 + decryptor.finalize()
            deciphered_message = deciphered_message.decode()

        return deciphered_message, nonce, cipher_suite

    def generate_secure_receipt(self, message, nonce,
                                peer_rsa_pubkey, cipher_suite):
        # Generate receipt from cleartext message and timestamp
        message_digest = base64.b64encode(digest_payload(
            message, cipher_suite['sha']['size'])).decode()

        receipt = {
            'nonce': base64.b64encode(nonce).decode(),
            'hashed_timestamp_message': base64.b64encode(digest_payload(
                message_digest + str(time.time()),
                cipher_suite['sha']['size'])).decode(),
            'signature': None
        }

        # Sign receipt message
        receipt['signature'] = base64.b64encode(cc.sign(
            json.dumps(receipt['hashed_timestamp_message']).encode(),
            self.cc_pin)).decode()

        # Cipher receipt
        aes_key = os.urandom(cipher_suite['aes']['key_size'])
        aes_cipher, aes_iv = generate_aes_cipher(
            aes_key, cipher_suite['aes']['mode'])

        encryptor = aes_cipher.encryptor()
        ciphered_receipt = encryptor.update(json.dumps(receipt).encode()) + \
                           encryptor.finalize()

        # Cipher nonce and AES key and IV
        aes_iv_key = aes_iv + aes_key
        ciphered_aes_iv_key = rsa_cipher(
            peer_rsa_pubkey,
            aes_iv_key,
            cipher_suite['sha']['size'],
            cipher_suite['rsa']['cipher']['padding']
        )

        payload = {
            'payload': {
                'receipt': base64.b64encode(ciphered_receipt).decode(),
                'key_iv': base64.b64encode(ciphered_aes_iv_key).decode()
            },
            'signature': None,
            'cipher_spec': cipher_suite
        }

        # Sign payload
        payload['signature'] = base64.b64encode(
            cc.sign(json.dumps(payload['payload']).encode(),
                    self.cc_pin)).decode()

        return base64.b64encode(json.dumps(payload).encode()).decode()

    def decipher_secure_receipt(self, payload, peer_certificate):
        payload = json.loads(base64.b64decode(payload.encode()))
        deciphered_receipt = None

        # Validate receipt signature
        try:
            rsa_verify(
                peer_certificate.get_pubkey().to_cryptography_key(),
                base64.b64decode(payload['signature']),
                json.dumps(payload['payload']).encode(),
                self.cipher_suite['rsa']['sign']['cc']['sha'],
                self.cipher_suite['rsa']['sign']['cc']['padding']
            )
        except InvalidSignature:
            logger.log(logging.DEBUG, "Invalid receipt signature")
            deciphered_receipt = {'error': 'Invalid receipt signature'}

        if deciphered_receipt is None:
            # Decipher AES key and IV
            aes_iv_key = rsa_decipher(
                self.private_key,
                base64.b64decode(payload['payload']['key_iv'].encode()),
                self.cipher_suite['sha']['size'],
                self.cipher_suite['rsa']['cipher']['padding']
            )

            # If the user can't decrypt, return error message
            if isinstance(aes_iv_key, dict) \
                    and 'error' in aes_iv_key:
                return aes_iv_key

            aes_iv = aes_iv_key[0:16]
            aes_key = aes_iv_key[16:]

            # Decipher payload
            aes_cipher, aes_iv = generate_aes_cipher(
                aes_key, self.cipher_suite['aes']['mode'], aes_iv)

            decryptor = aes_cipher.decryptor()
            deciphered_receipt = decryptor.update(
                base64.b64decode(payload['payload']['receipt'].encode())) \
                                 + decryptor.finalize()
            deciphered_receipt = json.loads(deciphered_receipt.decode())

        return deciphered_receipt

    def verify_secure_receipts(self, result, peer_certificate):
        # Decipher original sent message
        deciphered_message, nonce, cipher_suite = \
            self.decipher_message_from_user(result['msg'])

        to_rtn = {'error': 'Cannot decipher message nor receipts'} \
            if 'error' in deciphered_message else None

        if peer_certificate is None:
            to_rtn = {'error': 'Invalid peer certificate'}

        # Validate receipts sender certificate
        # Verify certificate validity
        if to_rtn is None and \
                not self.certificates.validate_cert(peer_certificate):
            logger.log(logging.DEBUG, "Invalid certificate; "
                                      "droping message")
            to_rtn = {'error': 'Invalid peer certificate'}

        if to_rtn is None:
            to_rtn = {'msg': deciphered_message, 'receipts': []}
            for r in result['receipts']:
                # Decipher receipt
                deciphered_receipt = self.decipher_secure_receipt(
                    r['receipt'], peer_certificate)

                receipt = {
                    'date': r['date'],
                    'id': r['id'],
                    'receipt': None
                }

                if 'error' in deciphered_receipt:
                    receipt['receipt'] = deciphered_receipt
                else:
                    receipt_nonce = base64.b64decode(
                        deciphered_receipt['nonce'].encode())

                    # Validate nonce, actually proves that the message was read
                    if nonce == receipt_nonce:
                        receipt['receipt'] = {
                            'hash': deciphered_receipt[
                                'hashed_timestamp_message'],
                            'signature': deciphered_receipt['signature']
                        }
                    else:
                        receipt['receipt'] = \
                            {'error': 'Invalid nonce; invalid receipt'}

                to_rtn['receipts'] += [receipt]

        return to_rtn
