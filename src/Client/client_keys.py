from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
import os


def generate_rsa_keypair(size):
    if size != 2048:
        return None

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=size,
        backend=default_backend()
    )

    return private_key, private_key.public_key()


def generate_aes_cipher(key, mode):
    if len(key) * 8 not in [192, 256]:
        return None

    iv = os.urandom(16)
    cipher_modes = {
        'CFB': modes.CFB(iv),
        'CTR': modes.CTR(iv)
    }

    if mode not in cipher_modes.keys():
        return None

    cipher = Cipher(algorithms.AES(key), cipher_modes[mode],
                    backend=default_backend())

    return cipher, iv


def derive_key(password, length, algorithm, salt):
    if password is None:
        return None

    if length * 8 not in [192, 256]:
        return None

    hash_algorithms = {
        'SHA256': hashes.SHA256(),
        'SHA384': hashes.SHA384()
    }

    if algorithm not in hash_algorithms.keys():
        return None

    if salt is None:
        return None

    info = b"hkdf-password-derivation"
    hkdf = HKDF(
        algorithm=hash_algorithms[algorithm],
        length=length,
        salt=salt,
        info=info,
        backend=default_backend()
    )

    password = password if isinstance(password, bytes) else password.encode()
    key = hkdf.derive(password)

    return key, salt


def digest_payload(payload, algorithm):
    if payload is None:
        return None

    hash_algorithms = {
        'SHA256': hashes.SHA256(),
        'SHA384': hashes.SHA384()
    }

    if algorithm not in hash_algorithms.keys():
        return None

    payload = payload if isinstance(payload, bytes) else payload.encode()
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(payload)
    hashed_payload = digest.finalize()

    return hashed_payload


def generate_ecdh_keypair():
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())

    return private_key, private_key.public_key()


def derive_key_from_ecdh(private_key, peer_pubkey, priv_salt, pub_salt,
                         length, algorithm):
    if private_key is None or peer_pubkey is None:
        return None

    shared_secret = private_key.exchange(ec.ECDH(), peer_pubkey)
    return derive_key(shared_secret, length, algorithm, priv_salt + pub_salt)


def save_to_ciphered_file(password, payload, location):
    pass