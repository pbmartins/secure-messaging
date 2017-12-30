from pkcs11.constants import Attribute
from pkcs11.constants import ObjectClass
from OpenSSL import crypto
from termcolor import colored
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
    print(colored('ERROR: CC device not connected', 'red'))
    sys.exit(0)


def get_correct_pin():
    pin = getpass.getpass(colored("CC Authentication PIN: ", 'blue'))

    # Get correct pin
    text = "\nIncorrect PIN. Please type the correct PIN: "
    while not test_pin(pin):
        pin = getpass.getpass(colored(text, 'red'))

    return pin


def test_pin(cc_pin):
    try:
        with token.open(user_pin=cc_pin) as session:
            return True
    except:
        return False


def get_public_key():
    try:
        # Open a session on our token
        with token.open() as session:
            pub_keys = session.get_objects(
                {Attribute.CLASS: ObjectClass.PUBLIC_KEY})

            pub_key = None
            for key in pub_keys:
                if "AUTH" in key[Attribute.LABEL].upper():
                    pub_key = key
                    break

            print(pub_key)
            pub_keys = None

            return pub_key
    except AttributeError:
        print(colored('ERROR: CC device not connected', 'red'))
        sys.exit(0)


def get_pub_key_certificate():
    cert = None

    try:
        with token.open() as session:
            # Get Citizen certificate
            cc_certs = session.get_objects(
                {Attribute.CLASS: ObjectClass.CERTIFICATE})

            for cc_cert in cc_certs:
                # Convert from DER-encoded value
                cert = crypto.load_certificate(
                    crypto.FILETYPE_ASN1, cc_cert[Attribute.VALUE])

                issuer = cert.get_issuer().commonName
                if 'EC de Autenticação do Cartão de Cidadão 00' in issuer:
                    break

            cc_certs = None

        return cert
    except AttributeError:
        print(colored('ERROR: CC device not connected', 'red'))
        sys.exit(0)


def sign(payload, cc_pin=None):
    pin = get_correct_pin() if cc_pin is None else cc_pin

    try:
        # Open a session on our token
        with token.open(user_pin=pin) as session:
            # Get an RSA keypair in this session
            priv_keys = session.get_objects(
                {Attribute.CLASS: ObjectClass.PRIVATE_KEY})

            priv_key = None
            for key in priv_keys:
                if "AUTH" in str(key).upper():
                    priv_key = key
                    break

            # Sign data
            signature = priv_key.sign(
                payload, mechanism=pkcs11.Mechanism.SHA256_RSA_PKCS
            )

            priv_keys = None
            return signature
    except AttributeError:
        print(colored('ERROR: CC device not connected', 'red'))
        sys.exit(0)


def verify(pub_key, payload, signature):
    # Verify signature
    return pub_key.verify(
        payload, signature, mechanism=pkcs11.Mechanism.SHA256_RSA_PKCS)
