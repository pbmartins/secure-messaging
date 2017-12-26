from src.Client.lib import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from OpenSSL import crypto
import pkcs11
import os
import base64


def get_nounce(byte_size, message, hash_algorithm):
    return digest_payload(message + os.urandom(byte_size), hash_algorithm) 


def get_hash_algorithm(algorithm):
    hash_algorithms = {
        256: hashes.SHA256(),
        384: hashes.SHA384()
    }

    assert algorithm in hash_algorithms.keys()
    return hash_algorithms[algorithm]


def get_aes_mode(mode, iv):
    cipher_modes = {
        'CFB': modes.CFB(iv),
        'CTR': modes.CTR(iv)
    }

    assert mode in cipher_modes.keys()
    return cipher_modes[mode]


def get_padding_algorithm(padding_mode, h):
    paddings = {
        'OAEP': padding.OAEP(
            mgf=padding.MGF1(algorithm=h),
            algorithm=h,
            label=None
        ),
        'PKCS1v15': padding.PKCS1v15(),
        'PSS': padding.PSS(
            mgf=padding.MGF1(h),
            salt_length=padding.PSS.MAX_LENGTH
        )
    }

    assert padding_mode in paddings.keys()
    return paddings[padding_mode]


def generate_rsa_keypair(size):
    assert size in [1024, 2048]

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=size,
        backend=default_backend()
    )

    return private_key, private_key.public_key()


def generate_aes_cipher(key, mode, iv=None):
    assert len(key) * 8 in [192, 256]

    iv = os.urandom(16) if iv is None else iv
    cipher_mode = get_aes_mode(mode, iv)
    cipher = Cipher(algorithms.AES(key), cipher_mode, backend=default_backend())

    return cipher, iv


def derive_key(password, length, hash_algorithm, salt):
    assert password is not None
    assert length * 8 in [192, 256]
    assert salt is not None

    h = get_hash_algorithm(hash_algorithm)

    info = b"hkdf-password-derivation"
    hkdf = HKDF(
        algorithm=h,
        length=length,
        salt=salt,
        info=info,
        backend=default_backend()
    )

    password = password if isinstance(password, bytes) else password.encode()
    key = hkdf.derive(password)

    return key


def digest_payload(payload, hash_algorithm):
    assert payload is not None

    h = get_hash_algorithm(hash_algorithm)

    payload = payload if isinstance(payload, bytes) else payload.encode()
    digest = hashes.Hash(h, backend=default_backend())
    digest.update(payload)
    hashed_payload = digest.finalize()

    return hashed_payload

"""
    Key exchange operations
"""


def generate_ecdh_keypair():
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    return private_key, private_key.public_key()


def derive_key_from_ecdh(private_key, peer_pubkey, priv_salt, pub_salt,
                         length, hash_algorithm, number_of_derivations):
    assert private_key is not None and peer_pubkey is not None
    assert number_of_derivations > 0

    shared_secret = private_key.exchange(ec.ECDH(), peer_pubkey)
    key = derive_key(shared_secret, length, hash_algorithm, priv_salt+pub_salt)

    for i in range(1, number_of_derivations):
        key = derive_key(key, length, hash_algorithm, priv_salt+pub_salt)

    return key


"""
    File operations
"""


def save_to_ciphered_file(password, payload, uuid):
    f = open(os.path.join(KEYS_DIR + str(uuid) + '/priv_rsa'), 'wb')

    password = password if isinstance(password, bytes) else password.encode()

    # Cipher payload
    file_payload = payload.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.BestAvailableEncryption(password))

    f.write(file_payload)
    f.close()


def save_to_file(payload, uuid):
    f = open(os.path.join(KEYS_DIR + str(uuid) + '/pub_rsa'), 'wb')

    file_payload = payload.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)

    # Save to file
    f.write(file_payload)
    f.close()


def read_from_ciphered_file(password, uuid):
    f = open(os.path.join(KEYS_DIR + str(uuid) + '/priv_rsa'), 'rb')

    password = password if isinstance(password, bytes) else password.encode()

    # Decipher payload
    payload = serialization.load_pem_private_key(f.read(), password, default_backend())
    f.close()
    return payload


def read_from_file(uuid):
    f = open(os.path.join(KEYS_DIR + str(uuid) + '/pub_rsa'), 'rb')

    # Read from file
    payload = serialization.load_pem_public_key(f.read(), default_backend())
    return payload


"""
    Assymetric operations
"""


def rsa_sign(private_key, payload, hash_algorithm, padding_algorithm):
    h = get_hash_algorithm(hash_algorithm)
    p = get_padding_algorithm(padding_algorithm, h)
    signature = private_key.sign(payload, p, h)
    return signature


def rsa_verify(public_key, signature, payload, hash_algorithm, padding_algorithm):
    h = get_hash_algorithm(hash_algorithm)
    p = get_padding_algorithm(padding_algorithm, h)
    return public_key.verify(signature, payload, p, h)


def rsa_cipher(public_key, payload, hash_algorithm, padding_algorithm):
    h = get_hash_algorithm(hash_algorithm)
    p = get_padding_algorithm(padding_algorithm, h)
    ciphertext = public_key.encrypt(payload, p)
    return ciphertext


def rsa_decipher(private_key, ciphertext, hash_algorithm, padding_algorithm):
    h = get_hash_algorithm(hash_algorithm)
    p = get_padding_algorithm(padding_algorithm, h)
    payload = private_key.decrypt(ciphertext, p)
    return payload


"""
Other utilities
"""


def get_cipher_suite(cipher_spec):
    specs = cipher_spec.split('-')
    aes = specs[1].split('_')
    rsa = specs[2].split('_')
    rsasign = specs[3].split('_')
    hash = specs[4]

    cipher_suite = {
        'aes': {
            'key_size': int(aes[0][3:]) // 8,
            'mode': aes[1]
        },
        'rsa': {
            'cipher': {
                'key_size': int(rsa[0][3:]),
                'padding': rsa[1]
            },
            'sign': {
                'key_size': int(rsasign[0][3:]),
                'server': {
                    'padding': rsasign[1],
                    'sha': int(rsasign[2][3:])
                },
                'cc': {
                    'padding': rsasign[3],
                    'sha': int(rsasign[4][3:])
                },
            }
        },
        'sha': {
            'size': int(hash[3:])
        }
    }
    return cipher_suite


def serialize_key(pub_value):
    return base64.b64encode(pub_value.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)).decode()


def deserialize_key(pub_value):
    return serialization.load_pem_public_key(base64.b64decode(
        pub_value.encode()), default_backend())


def serialize_certificate(cert):
    return base64.b64encode(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert)).decode()


def deserialize_certificate(cert):
    return crypto.load_certificate(crypto.FILETYPE_PEM,
                                   base64.b64decode(cert.encode()))