from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
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


def get_padding_algorithm(padding_mode):
    paddings = {
        'OAEP': padding.OAEP,
        'PKCS1v15': padding.OAEP
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
    dir_path = os.path.dirname(os.path.realpath(__file__))
    f = open(os.path.join(dir_path, 'keys/' + uuid + '/priv_rsa'), 'wb')

    password = password if isinstance(password, bytes) else password.encode()

    # Cipher payload
    file_payload = payload.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.BestAvailableEncryption(password))

    f.write(file_payload)
    f.close()


def save_to_file(payload, uuid):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    f = open(os.path.join(dir_path, 'keys/' + uuid + '/pub_rsa'), 'wb')

    file_payload = payload.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)

    # Save to file
    f.write(file_payload)
    f.close()


def read_from_ciphered_file(password, uuid):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    f = open(os.path.join(dir_path, 'keys/' + uuid + '/priv_rsa'), 'rb')

    password = password if isinstance(password, bytes) else password.encode()

    # Decipher payload
    payload = serialization.load_pem_private_key(f.read(), password, default_backend())

    f.close()

    return payload


def read_from_file(uuid):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    f = open(os.path.join(dir_path, 'keys/' + uuid + '/pub_rsa'), 'rb')

    # Read from file
    payload = serialization.load_pem_public_key(f.read(), default_backend())

    return payload


"""
    Assymetric operations
"""


def rsa_sign(private_key, payload, hash_algorithm):
    h = get_hash_algorithm(hash_algorithm)
    signature = private_key.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(h),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        h
    )
    return signature


def rsa_verify(public_key, signature, payload, hash_algorithm):
    h = get_hash_algorithm(hash_algorithm)
    return public_key.verify(
        signature,
        payload,
        padding.PSS(
            mgf=padding.MGF1(h),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        h
    )


def rsa_cipher(public_key, payload, hash_algorithm, padding_algorithm):
    h = get_hash_algorithm(hash_algorithm)
    p = get_padding_algorithm(padding_algorithm)
    ciphertext = public_key.encrypt(
        payload,
        p(
            mgf=padding.MGF1(algorithm=h),
            algorithm=h,
            label=None
        )
    )
    return ciphertext


def rsa_decipher(private_key, ciphertext, hash_algorithm, padding_algorithm):
    h = get_hash_algorithm(hash_algorithm)
    p = get_padding_algorithm(padding_algorithm)
    payload = private_key.decrypt(
        ciphertext,
        p(
            mgf=padding.MGF1(algorithm=h),
            algorithm=h,
            label=None
        )
    )
    return payload
