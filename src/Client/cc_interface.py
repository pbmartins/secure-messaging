from pkcs11.constants import Attribute
from pkcs11.constants import ObjectClass
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import hashes
from OpenSSL import crypto
import pkcs11
import getpass
import os
import sys

lib = pkcs11.lib(os.environ['PKCS11_MODULE'])
token = None
try:
    for t in lib.get_tokens():
        token = t
        break
except AttributeError:
    print('ERROR: CC device not connected')
    sys.exit(0)


def get_public_key():
    try:
        # Open a session on our token
        with token.open() as session:
            pub_keys = session.get_objects({Attribute.CLASS: ObjectClass.PUBLIC_KEY})

            pub_key = None
            for key in pub_keys:
                if "AUTH" in str(key).upper():
                    pub_key = key
                    break

            return pub_key
    except AttributeError:
        print('ERROR: CC device not connected')
        sys.exit(0)


def get_pub_key_certificate():
    cert = None

    try:
        with token.open() as session:
            # Get Citizen certificate
            cc_certs = session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE})

            for cc_cert in cc_certs:
                # Convert from DER-encoded value
                cert = crypto.X509.from_cryptography(
                    x509.load_der_x509_certificate(cc_cert[Attribute.VALUE],
                                                   default_backend())
                )

                issuer = cert.get_issuer().commonName
                if 'EC de Autenticação do Cartão de Cidadão 00' in issuer:
                    break

            cc_certs = None

        return cert
    except AttributeError:
        print('ERROR: CC device not connected')
        sys.exit(0)


def sign(payload):
    pin = getpass.getpass("Signature PIN: ")

    try:
        # Open a session on our token
        with token.open(user_pin=pin) as session:
            # Generate an RSA keypair in this session
            priv_keys = session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY})

            priv_key = None
            for key in priv_keys:
                if "AUTH" in str(key).upper():
                    priv_key = key
                    break

            # Sign data
            signature = priv_key.sign(
                payload, mechanism=pkcs11.Mechanism.SHA1_RSA_PKCS)
            return signature
    except AttributeError:
        print('ERROR: CC device not connected')
        sys.exit(0)


def verify(pub_key, payload, signature):
    # Verify signature
    return pub_key.verify(
        payload, signature, mechanism=pkcs11.Mechanism.SHA1_RSA_PKCS)
