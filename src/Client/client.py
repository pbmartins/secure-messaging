from socket import *
from src.Client.cc_interface import *
from src.Client.cipher_utils import *
from src.Client.client_secure import *
import json
import getpass
import base64
import os
import time

# Server address
HOST = ""   # All available interfaces
PORT = 8080  # The server port

BUFSIZE = 512 * 1024
TERMINATOR = "\n\n"
MAX_BUFSIZE = 64 * 1024

DIR_PATH = os.path.dirname(os.path.realpath(__file__))


class Client:
    @staticmethod
    def choose_cipher_spec():
        suites = [
            "EECDH-AES192_CFB-RSA1024_PCKS1v15-SHA256",
            "EECDH-AES192_CFB-RSA2048_OAEP-SHA256",
            "EECDH-AES256_CFB-RSA2048_OAEP-SHA384",
            "EECDH-AES192_CTR-RSA1024_PCKS1v15-SHA256",
            "EECDH-AES192_CTR-RSA2048_OAEP-SHA256",
            "EECDH-AES256_CTR-RSA2048_OAEP-SHA384"
        ]

        print("--- Choose cipher suite ---\n"
              "0 - EECDH-AES192_CFB-RSA1024_PCKS1v15-SHA256\n"
              "1 - EECDH-AES192_CFB-RSA2048_OAEP-SHA256\n"
              "2 - EECDH-AES256_CFB-RSA2048_OAEP-SHA384\n"
              "3 - EECDH-AES192_CTR-RSA1024_PCKS1v15-SHA256\n"
              "4 - EECDH-AES192_CTR-RSA2048_OAEP-SHA256\n"
              "5 - EECDH-AES256_CTR-RSA2048_OAEP-SHA384")
        op = int(input("Cipher suite -> "))

        while op < 0 or op > 5:
            op = int(input("Cipher suite -> "))

        return suites[op]

    def __init__(self):
        self.ss = socket(AF_INET, SOCK_STREAM)
        self.ss.connect((HOST, 8080))
        self.uuid = None
        self.user_id = None
        self.password = None
        self.secure = None
        self.cc_certificate = None

    def send_payload(self, message):
        self.ss.send(json.dumps(message)[:BUFSIZE].encode('utf-8')
                + '\r\n'.encode('utf-8'))
        data = json.loads(self.ss.recv(BUFSIZE).decode('utf-8').split(TERMINATOR)[0])
        return data

    def login(self):
        print("-------- LOGIN --------")
        print("Make sure you have your CC inserted.")
        print("If you don't have an account, it'll be automatically created.")
        self.cc_certificate = get_pub_key_certificate()
        self.uuid = self.cc_certificate.digest()
        self.password = getpass.getpass("Password: ")

        cipher_suite = ClientSecure.get_cipher_suite(Client.choose_cipher_spec())

        # Generate RSA keys and save them into file
        key_dir = DIR_PATH + 'keys/' + self.uuid
        if not os.path.exists(key_dir):
            os.makedirs(key_dir)
            priv_key, pub_key = generate_rsa_keypair(cipher_suite['rsa']['key_size'])

            # Save private key to ciphered file
            save_to_ciphered_file(
                self.password,
                cipher_suite['aes']['key_size'],
                cipher_suite['sha']['size'],
                cipher_suite['aes']['mode'],
                priv_key,
                self.uuid
            )

            # Save public key to regular file
            save_to_file(pub_key, self.uuid)

            # Initialize session with the server
            self.secure = ClientSecure(cipher_suite, priv_key, pub_key)
            data = self.send_payload(self.secure.encapsulate_insecure_message())
            message = self.secure.uncapsulate_secure_message(data)

            # Create user account
            self.create_user()

        else:
            # Read private key from ciphered file
            priv_key = read_from_ciphered_file(
                self.password,
                cipher_suite['aes']['key_size'],
                cipher_suite['sha']['size'],
                cipher_suite['aes']['mode'],
                self.uuid
            )

            # Read public key from regular file
            pub_key = read_from_file(self.uuid)

            # Initialize session with the server
            self.secure = ClientSecure(cipher_suite, priv_key, pub_key)
            data = self.send_payload(self.secure.encapsulate_insecure_message())
            message = self.secure.uncapsulate_secure_message(data)

    def create_user(self):
        payload = {
            'type': 'create',
            'uuid': self.uuid,
            'secdata': {
                'rsapubkey':
                    self.cc_certificate.get_pubkey().to_cryptography_key(),
                'cccertificate': self.cc_certificate
            }
        }

        data = self.send_payload(self.secure.encapsulate_secure_message(payload))
        data = self.secure.uncapsulate_secure_message(data)

        if 'error' in data:
            print("ERROR: " + data['error'])
        else:
            self.user_id = data['result']

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

            payload['msg'] = json.dumps(payload['msg'])
            payload['copy'] = payload['msg']

        # Get receiver public key and certificate
        resource_payload = self.secure.encapsulate_resource_message(payload['dst'])
        if resource_payload is not None:
            data = self.send_payload(
                self.secure.encapsulate_secure_message(resource_payload))
            self.secure.uncapsulate_resource_message(
                self.secure.uncapsulate_secure_message(data))

        # Cipher message
        payload['msg'] = self.secure.cipher_message_to_user(
            payload['msg'], 'message', payload['dst'])

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
            message = self.secure.decipher_message_from_user(data['result'][1])
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
        resource_payload = self.secure.encapsulate_resource_message(payload['id'])
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
