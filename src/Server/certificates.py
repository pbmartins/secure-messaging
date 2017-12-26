from src.Server.log import logger
from src.Server.lib import *
from OpenSSL import crypto
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import wget
import os
import base64
import logging


# Only accepts OpenSSL X509 Objects
class X509Certificates:
    @staticmethod
    def deserialize_certificate(cert):
        return crypto.load_certificate(crypto.FILETYPE_PEM,
                                       base64.b64decode(cert.encode()))
    @classmethod
    def get_extension(cls, cert, short_name):
        for i in range(0, cert.get_extension_count()):
            extension = cert.get_extension(i)
            if extension.get_short_name() == short_name:
                return extension

    @classmethod
    def get_crl_url(cls, cert):
        extension = cls.get_extension(cert, b'crlDistributionPoints')
        try:
            value = extension.get_data()
            url = 'http' + value.split(b'http')[1].decode()
            return url
        except:
            return None

    @classmethod
    def get_ocsp_url(cls, cert):
        extension = cls.get_extension(cert, b'authorityInfoAccess')
        try:
            value = extension.get_data()
            url = 'http' + value.split(b'http')[1].decode()
            return url
        except:
            return None

    def __init__(self, users):
        self.priv_key = None
        self.pub_key = None
        self.cert = None
        self.ca_cert = None
        self.crls = {}
        self.certs = {}

        self.store = crypto.X509Store()
        self.import_user_certs(users)
        self.import_certs(XCA_DIR)
        self.import_certs(CERTS_DIR)
        self.import_keys()

    def import_user_certs(self, users):
        for uid in users:
            user = users[uid]
            cc_cert = X509Certificates.deserialize_certificate(
                user['description']['secdata']['cccertificate'])
            self.certs[user['id']] = cc_cert
            self.store.add_cert(cc_cert)

    def import_certs(self, directory):
        files = [f for f in os.listdir(directory)]
        certs = {}

        for f_name in files:
            cert = None

            # Trying to read it as PEM
            try:
                f = open(directory + f_name, 'rb')
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
            except crypto.Error:
                logger.log(logging.DEBUG, "Not a PEM Certificate: %r" % f_name)
            finally:
                f.close()

            if cert is None:
                # Trying to read it as DER
                try:
                    f = open(directory + f_name, 'rb')
                    cert = crypto.load_certificate(
                        crypto.FILETYPE_ASN1, f.read())
                    logger.log(logging.DEBUG,
                               "Loaded DER Certificate: %r" % f_name)
                    f.close()
                except crypto.Error:
                    logger.log(logging.DEBUG,
                               "Unable to load certificate: %r" % f_name)
                    f.close()
                    continue

            if cert.get_subject().commonName == 'SecurityServer':
                self.cert = cert
            elif cert.get_subject().commonName == 'ServerCA':
                self.ca_cert = cert
            elif cert.get_subject().commonName not in self.certs.keys():
                certs[cert.get_subject().commonName] = cert
                self.certs[cert.get_subject().commonName] = cert

        for subject in certs.keys():
            self.store.add_cert(certs[subject])

    def import_keys(self):
        f = open(XCA_DIR + 'SecurityServer.pem', 'rb')

        self.priv_key = serialization.load_pem_private_key(
            f.read(), None, default_backend())
        self.pub_key = self.cert.get_pubkey().to_cryptography_key()

    # TODO: Check CRL date periodically
    def check_expiration_or_revoked(self, cert):
        # Check time validity
        if cert.has_expired():
            return False

        # Check if it has been revoked
        issuer = cert.get_issuer().commonName
        if issuer not in self.crls:
            crl_download = wget.download(
                X509Certificates.get_crl_url(cert), out=CRLS_DIR[:-1])
            print(crl_download)

            f = open(crl_download, 'rb')
            crl = crypto.load_crl(crypto.FILETYPE_ASN1, f.read())

            self.crls[issuer] = crl_download
        else:
            f = open(self.crls[issuer], 'rb')
            crl = crypto.load_crl(crypto.FILETYPE_ASN1, f.read())

        revoked_serials = [int(c.get_serial(), 16) for c in crl.get_revoked()]
        return cert.get_serial_number() not in revoked_serials

    # TODO: Check all the chain
    def validate_cert(self, cert):
        c = cert

        logger.log(logging.DEBUG, "Verifying certificate validity: %r"
                   % cert.get_issuer.commonName)
        # Check if all certificates in the chain are valid
        while True:
            if c.get_issuer().commonName not in self.certs.keys():
                return False

            if c.get_issuer().commonName == c.get_subject().commonName:
                break

            if not self.check_expiration_or_revoked(c):
                return False
            c = self.certs[c.get_issuer().commonName]

        # Check if the chain is valid
        try:
            # Create a certificate context using the store and
            # the certificate to be verified
            store_ctx = crypto.X509StoreContext(self.store, cert)

            # Verify the certificate, returns None
            # if it can validate the certificate
            store_ctx.verify_certificate()

            # If it gets here, it means it's valid
            return True

        except Exception as e:
            return False
