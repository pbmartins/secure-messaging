from socket import *
from src.Client.cc_interface import *
from src.Client.cipher_utils import *
from src.Client.client_secure import *
from src.Client.log import logger
from src.Client.lib import *
import json
import getpass
import base64
import os
import time
import logging

# Server address
HOST = ""   # All available interfaces
PORT = 8080  # The server port

BUFSIZE = 512 * 1024
TERMINATOR = "\n\n"
MAX_BUFSIZE = 64 * 1024


class Client:
    @staticmethod
    def choose_cipher_spec():
        suites = [
            "EECDH-AES192_CFB-RSA1024_PCKS1v15-RSA2048_PSS_SHA256_PKCS1v15_SHA256-SHA256",
            "EECDH-AES192_CFB-RSA2048_OAEP-RSA2048_PSS_SHA256_PKCS1v15_SHA256-SHA256",
            "EECDH-AES256_CFB-RSA2048_OAEP-RSA2048_PSS_SHA384_PKCS1v15_SHA256-SHA384",
            "EECDH-AES192_CTR-RSA1024_PCKS1v15-RSA2048_PSS_SHA256_PKCS1v15_SHA256-SHA256",
            "EECDH-AES192_CTR-RSA2048_OAEP-RSA2048_PSS_SHA256_PKCS1v15_SHA256-SHA256",
            "EECDH-AES256_CTR-RSA2048_OAEP-RSA2048_PSS_SHA384_PKCS1v15_SHA256-SHA384"
        ]

        print("\n--- Choose cipher suite ---"
              "\n0 - " + suites[0] +
              "\n1 - " + suites[1] +
              "\n2 - " + suites[2] +
              "\n3 - " + suites[3] +
              "\n4 - " + suites[4] +
              "\n5 - " + suites[5]
              )
        op = int(input("Cipher suite -> "))

        while op < 0 or op > 5:
            op = int(input("Cipher suite -> "))

        return suites[op]

    @staticmethod
    def cache_cc_pin():
        op = input("Do you wish to cache your CC Signature PIN? [y/N]")
        while op != 'y' and op != 'N':
            op = input("Do you wish to cache your CC Signature PIN? [y/N]")

        pin = getpass.getpass("CC Authentication PIN: ") if op == 'y' else None
        return pin

    def __init__(self):
        self.ss = socket(AF_INET, SOCK_STREAM)
        self.ss.connect((HOST, 8080))
        self.uuid = None
        self.user_id = None
        self.password = None
        self.secure = None
        self.cc_certificate = None

        self.login()

    def send_payload(self, message):
        to_send = json.dumps(message)
        while len(to_send):
            self.ss.send(to_send[:BUFSIZE].encode('utf-8')
                         + '\r\n'.encode('utf-8'))
            to_send = to_send[BUFSIZE:]

        data = json.loads(self.ss.recv(BUFSIZE).decode('utf-8').split(TERMINATOR)[0])
        return data

    def login(self):
        print("-------- LOGIN --------")
        print("Make sure you have your CC inserted.")
        print("If you don't have an account, it'll be automatically created.")
        self.cc_certificate = get_pub_key_certificate()
        self.uuid = int(
            self.cc_certificate.digest('sha256').decode().replace(':', ''), 16)
        print('Login with ', self.uuid, '\n')
        self.password = getpass.getpass("\nPassword: ")

        # Generate RSA keys and save them into file
        key_dir = KEYS_DIR + str(self.uuid)
        if not os.path.exists(key_dir):
            # Chose cipher spec
            cipher_spec = Client.choose_cipher_spec()
            cipher_suite = get_cipher_suite(cipher_spec)

            # Create directory to save keys
            os.makedirs(key_dir)
            priv_key, pub_key = \
                generate_rsa_keypair(cipher_suite['rsa']['cipher']['key_size'])

            # Save private key to ciphered file
            save_to_ciphered_file(
                self.password,
                priv_key,
                self.uuid
            )

            # Save public key to regular file
            save_to_file(pub_key, self.uuid)

            # Cache CC pin
            pin = Client.cache_cc_pin()

            # Initialize session with the server
            self.secure = ClientSecure(self.uuid, priv_key, pub_key,
                                       cipher_spec, cipher_suite, pin)
            data = self.send_payload(self.secure.encapsulate_insecure_message())
            message = self.secure.uncapsulate_secure_message(data)

            logger.log(logging.DEBUG, "Secure session with server established")
            # Create user account
            self.create_user(cipher_spec)

        else:
            logger.log(logging.DEBUG, "Logging in")

            # Get correct password
            text = "\nIncorrect password. Please type the correct password: "
            while True:
                try:
                    # Read private key from ciphered file
                    priv_key = read_from_ciphered_file(
                        self.password,
                        self.uuid
                    )
                    break
                except:
                    self.password = getpass.getpass(text)

            # Read public key from regular file
            pub_key = read_from_file(self.uuid)

            # Cache CC pin
            pin = Client.cache_cc_pin()

            # Initialize session with the server
            self.secure = ClientSecure(self.uuid, priv_key, pub_key, pin=pin)
            data = self.send_payload(self.secure.encapsulate_insecure_message())
            message = self.secure.uncapsulate_secure_message(data)

            logger.log(logging.DEBUG, "Secure session with server established")

    def create_user(self, cipher_spec):
        logger.log(logging.DEBUG, "Creating user account")
        payload = {
            'type': 'create',
            'uuid': self.uuid,
            'secdata': {
                'rsapubkey': serialize_key(self.secure.public_key),
                'ccpubkey': serialize_key(
                        self.cc_certificate.get_pubkey().to_cryptography_key()),
                'cccertificate': serialize_certificate(self.cc_certificate),
                'cipher_spec': cipher_spec
            }
        }

        data = self.send_payload(self.secure.encapsulate_secure_message(payload))
        data = self.secure.uncapsulate_secure_message(data)

        if 'error' in data:
            print("ERROR: " + data['error'])
        else:
            self.user_id = data['result']

            logger.log(logging.DEBUG, "User account created")

    def list_message_boxes(self):
        payload = {
            'type': 'list'
            # security related fields
        }

        user_id = input("User ID (optional): ")
        if len(user_id):
            payload['id'] = int(user_id)

        data = self.send_payload(self.secure.encapsulate_secure_message(payload))
        data = self.secure.uncapsulate_secure_message(data)

        if 'error' in data:
            print("ERROR: " + data['error'])
        else:
            print("User UUID(s): ")
            for i in range(0, len(data['result'])):
                print(str.format("\tID: {:d} - UUID: {:d}",
                                 i + 1, data['result'][i]['uuid']))

    def list_all_new_messages(self):
        payload = {
            'type': 'new'
        }

        while True:
            try:
                payload['id'] = int(input("User ID: "))
                break
            except ValueError:
                print("ERROR: Invalid User ID")

        data = self.send_payload(self.secure.encapsulate_secure_message(payload))
        data = self.secure.uncapsulate_secure_message(data)

        if 'error' in data:
            print("ERROR: " + data['error'])
        else:
            print("New message(s): ")
            for message in data['result']:
                print("\t" + message)

    def list_all_messages(self):
        payload = {
            'type': 'all'
        }

        while True:
            try:
                payload['id'] = int(input("User ID: "))
                break
            except ValueError:
                print("ERROR: Invalid User ID")

        data = self.send_payload(self.secure.encapsulate_secure_message(payload))
        data = self.secure.uncapsulate_secure_message(data)

        if 'error' in data:
            print("ERROR: " + data['error'])
        else:
            print("All received messages: ")
            for message in data['result'][0]:
                print("\t" + message)

            print("\n\nAll sent messages: ")
            for message in data['result'][1]:
                print("\t" + message)

    def send_message(self):
        payload = {
            'type': 'send'
        }

        while True:
            try:
                payload['src'] = int(input("Sender User ID: "))
                break
            except ValueError:
                print("ERROR: Invalid User ID")

        while True:
            try:
                payload['dst'] = int(input("Receiver User ID: "))
                break
            except ValueError:
                print("ERROR: Invalid User ID")

        # Read message
        print("Message (two line breaks to send it):")
        payload['msg'] = ""
        line = ""
        while True:
            last_line = line
            line = input()
            payload['msg'] += line + "\n"
            if not len(line) and not len(last_line):
                break

        payload['copy'] = payload['msg']

        # Get receiver public key and certificate
        resource_payload = self.secure.encapsulate_resource_message([payload['dst']])
        if resource_payload is not None:
            data = self.send_payload(
                self.secure.encapsulate_secure_message(resource_payload))
            self.secure.uncapsulate_resource_message(
                self.secure.uncapsulate_secure_message(data))

        # Cipher message
        payload['msg'] = self.secure.cipher_message_to_user(
            'message', payload['msg'], payload['dst'])

        data = self.send_payload(self.secure.encapsulate_secure_message(payload))
        data = self.secure.uncapsulate_secure_message(data)

        if 'error' in data:
            print("ERROR: " + data['error'])
        else:
            print("Message ID: " + data['result'][0])
            print("Receipt ID: " + data['result'][1])

    def receive_message(self):
        payload = {
            'type': 'recv'
        }

        while True:
            try:
                payload['id'] = int(input("Message box's User ID: "))
                break
            except ValueError:
                print("ERROR: Invalid User ID")

        while True:
            try:
                payload['msg'] = str(input("Message ID: "))
                break
            except ValueError:
                print("ERROR: Invalid message ID")

        data = self.send_payload(self.secure.encapsulate_secure_message(payload))
        data = self.secure.uncapsulate_secure_message(data)

        if 'error' in data:
            print("ERROR: " + data['error'])
        else:
            print("Message Sender ID: " + data['result'][0])
            # Decipher message and remove trailing newlines
            message = self.secure.decipher_message_from_user(
                data['result'][1], None).rstrip()
            print("Message: " + message)

            # Send receipt
            self.receipt_message(data['result'][0], message, payload['id'])

    def receipt_message(self, message_id, message, receipt_user_id):
        payload = {
            'type': 'receipt',
            'id': receipt_user_id,
            'msg': message_id
        }

        # Get receiver public key and certificate
        resource_payload = self.secure.encapsulate_resource_message([payload['id']])
        if resource_payload is not None:
            data = self.send_payload(
                self.secure.encapsulate_secure_message(resource_payload))
            self.secure.uncapsulate_resource_message(
                self.secure.uncapsulate_secure_message(data))

        # Generate signed hash of timestamp|hashed message
        hash_algorithm = self.secure.cipher_suite['sha']['size']
        payload['hashed_timestamp_message'] = digest_payload(
            digest_payload(message, hash_algorithm) + time.time(), hash_algorithm)
        payload['signature'] = sign(payload['hashed_timestamp_message'])

        # Cipher message
        message = self.secure.cipher_message_to_user(
            payload, 'receipt', payload['id'])

        self.send_payload(self.secure.encapsulate_secure_message(message))

    def message_status(self):
        message = {
            'type': 'status'
            # security related fields
        }

        while True:
            try:
                message['id'] = int(input("Receipts box's User ID: "))
                break
            except ValueError:
                print("ERROR: Invalid User ID")

        while True:
            try:
                message['msg'] = str(input("Message ID: "))
                break
            except ValueError:
                print("ERROR: Invalid message ID")

        data = self.send_payload(self.secure.encapsulate_secure_message(message))
        data = self.secure.uncapsulate_secure_message(data)

        if 'error' in data:
            print("ERROR: " + data['error'])
        else:
            message = self.secure.decipher_message_from_user(
                data['result']['msg'])
            print("Message: " + message)
            print("\nAll receipts: ")
            for receipt in data['result']['receipts']:
                print("\tDate: " + receipt['date'])
                print("\tReceipt sender ID: " + receipt['id'])
                deciphered_receipt = self.secure.decipher_message_from_user(
                    receipt['receipt'])
                print("\tReceipt: " + deciphered_receipt)
                print("")


def main():
    """
    Show main menu.
    :return: 
    """

    logging.basicConfig(
        stream=sys.stdout,
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    client = Client()

    while True:
        print("")
        print("OPTIONS")
        print("1 - [LIST] List all user client boxes")
        print("2 - [NEW] List all new messages in a user's message box")
        print("3 - [ALL] List all messages in a user's message box")
        print("4 - [SEND] Send a new message")
        print("5 - [RECV] Receive a message from a user's message box")
        print("6 - [STATUS] Check the status of a previously sent message")
        print("0 - [EXIT] Exit client")
        op = int(input("Select an option: "))
        print("")

        if op == 0:
            break
        elif op == 1:
            client.list_message_boxes()
        elif op == 2:
            client.list_all_new_messages()
        elif op == 3:
            client.list_all_messages()
        elif op == 4:
            client.send_message()
        elif op == 5:
            client.receive_message()
        elif op == 6:
            client.message_status()

    client.ss.close()
    return


if __name__ == "__main__":
    main()
