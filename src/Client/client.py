from cc_interface import *
from cipher_utils import *
from client_secure import *
from log import logger
from lib import *
from socket import *
from termcolor import colored
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
            "EECDH-AES192_CFB-RSA1024_PKCS1v15-RSA2048_PSS_SHA256_PKCS1v15_SHA256-SHA256",
            "EECDH-AES192_CFB-RSA2048_OAEP-RSA2048_PSS_SHA256_PKCS1v15_SHA256-SHA256",
            "EECDH-AES256_CFB-RSA2048_OAEP-RSA2048_PSS_SHA384_PKCS1v15_SHA256-SHA384",
            "EECDH-AES192_CTR-RSA1024_PKCS1v15-RSA2048_PSS_SHA256_PKCS1v15_SHA256-SHA256",
            "EECDH-AES192_CTR-RSA2048_OAEP-RSA2048_PSS_SHA256_PKCS1v15_SHA256-SHA256",
            "EECDH-AES256_CTR-RSA2048_OAEP-RSA2048_PSS_SHA384_PKCS1v15_SHA256-SHA384"
        ]

        print("\n--- Choose cipher suite ---",
              "\n0 - %-75s (Not Recommended)" % suites[0],
              "\n1 - %-75s " % suites[1],
              "\n2 - %-75s (Recommended)" % suites[2],
              "\n3 - %-75s (Not Recommended)" % suites[3],
              "\n4 - %-75s " % suites[4],
              "\n5 - %-75s (Recommended)" % suites[5]
              )
        op = int(input("Cipher suite -> "))

        while op < 0 or op > 5:
            op = int(input("Cipher suite -> "))

        return suites[op]

    @staticmethod
    def cache_cc_pin():
        op = input(colored(
            "Do you wish to cache your CC Signature PIN? [y/N]", 'green'))
        while op != 'y' and op != 'N':
            op = input(colored(
                "Do you wish to cache your CC Signature PIN? [y/N]", 'green'))

        pin = get_correct_pin() if op == 'y' else None

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

    def send_payload(self, message, response=True):
        to_send = json.dumps(message)
        while len(to_send):
            self.ss.send(to_send[:BUFSIZE].encode('utf-8')
                         + '\r\n'.encode('utf-8'))
            to_send = to_send[BUFSIZE:]
        if response:
            try:
                data = json.loads(self.ss.recv(BUFSIZE).decode('utf-8').split(TERMINATOR)[0])
                return data
            except:
                print('ERROR: Invalid response from server', 'red')

    def get_resources(self, user_ids, resource_data=None):
        # Get receiver public key and certificate
        resource_payload = self.secure.encapsulate_resource_message(user_ids)
        if resource_payload is not None:
            if resource_data is None:
                data = self.send_payload(
                    self.secure.encapsulate_secure_message(resource_payload))
                resource_data = self.secure.uncapsulate_secure_message(data)

            if 'error' in resource_data:
                print(colored("ERROR: " + resource_data['error'], 'red'))
                return False
            elif resource_data['result'][0]['rsapubkey'] is None:
                print(colored('User does not exist', 'red'))
                return False

            self.secure.uncapsulate_resource_message(resource_data)

        return True

    def login(self):
        print(colored("-------- LOGIN --------", 'blue'))
        print(colored("Make sure you have your CC inserted.", 'blue'))
        print(colored(
            "If you don't have an account, it'll be automatically created.",
            'blue')
        )
        self.cc_certificate = get_pub_key_certificate()
        self.uuid = int(
            self.cc_certificate.digest('sha256').decode().replace(':', ''), 16)
        print(colored('Login with UUID ' + str(self.uuid) + '\n', 'blue'))
        self.password = getpass.getpass(colored("\nPassword: ", 'blue'))

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
                    self.password = getpass.getpass(colored(text, 'red'))

            # Read public key from regular file
            pub_key = read_from_file(self.uuid)

            # Cache CC pin
            pin = Client.cache_cc_pin()

            # Initialize session with the server
            self.secure = ClientSecure(self.uuid, priv_key, pub_key, pin=pin)
            data = self.send_payload(self.secure.encapsulate_insecure_message())
            message = self.secure.uncapsulate_secure_message(data)
            self.user_id = message['result']

            logger.log(logging.DEBUG, "Secure session with server established")

        print(colored("Your UserID: %d" % self.user_id, 'green'))

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
            print(colored("ERROR: " + data['error'], 'red'))
        else:
            self.user_id = data['result']
            logger.log(logging.DEBUG, "User account created")
            print(colored("User account succesfully created.", 'green'))

    def list_message_boxes(self):
        payload = {
            'type': 'list'
        }

        while True:
            try:
                user_id = input(colored("User ID (optional): ", 'blue'))
                if len(user_id):
                    payload['id'] = int(user_id)
                break
            except ValueError:
                print(colored("ERROR: Invalid User ID", 'red'))

        print(colored('\nGetting message boxes list ...\n', 'yellow'))

        data = self.send_payload(self.secure.encapsulate_secure_message(payload))
        data = self.secure.uncapsulate_secure_message(data)

        if 'error' in data:
            print(colored("ERROR: " + data['error'], 'red'))
        elif data['result'] is None:
            print(colored("No users found with id " + user_id, 'red'))
        else:
            print(colored("User UUID(s): ", 'green'))
            for user in data['result']:
                print(colored(str.format("\tID: {:d} - UUID: {:d}",
                                         user['id'], user['description']['uuid']),
                              'green'))

    def list_all_new_messages(self):
        payload = {
            'type': 'new'
        }

        while True:
            try:
                payload['id'] = int(input(colored("User ID: ", 'blue')))
                break
            except ValueError:
                print(colored("ERROR: Invalid User ID", 'red'))

        print(colored(str.format('\nGetting new messages for user {:d} ...\n',
                                 payload['id']), 'yellow'))

        data = self.send_payload(self.secure.encapsulate_secure_message(payload))
        data = self.secure.uncapsulate_secure_message(data)

        if 'error' in data:
            print(colored("ERROR: " + data['error'], 'red'))
        elif data['result']:
            print(colored("New message(s): ", 'green'))
            for message in data['result']:
                print(colored("\t" + message, 'green'))
        else:
            print(colored("No new message(s)", 'green'))

    def list_all_messages(self):
        payload = {
            'type': 'all'
        }

        while True:
            try:
                payload['id'] = int(input(colored("User ID: ", 'blue')))
                break
            except ValueError:
                print(colored("ERROR: Invalid User ID", 'red'))

        print(colored(str.format('\nGetting all messages for user {:d} ...\n',
                                 payload['id']), 'yellow'))

        data = self.send_payload(self.secure.encapsulate_secure_message(payload))
        data = self.secure.uncapsulate_secure_message(data)

        if 'error' in data:
            print(colored("ERROR: " + data['error'], 'red'))
        else:
            if data['result'][0]:
                print(colored("All received messages: ", 'green'))
                for message in data['result'][0]:
                    print(colored("\t" + message, 'green'))
            else:
                print(colored("No received messages", 'green'))

            if data['result'][1]:
                print(colored("\n\nAll sent messages: ", 'green'))
                for message in data['result'][1]:
                    print(colored("\t" + message, 'green'))
            else:
                print(colored("No sent messages", 'green'))

    def send_message(self):
        payload = {
            'type': 'send',
            'src': self.user_id
        }

        while True:
            try:
                payload['dst'] = int(input(colored("Receiver User ID: ", 'blue')))
                break
            except ValueError:
                print(colored("ERROR: Invalid User ID", 'red'))

        # Read message
        print(colored("Message (two line breaks to send it):", 'blue'))
        msg = ""

        while True:
            line = input()
            msg += line + "\n"
            if not len(line):
                break

        msg = base64.b64encode(msg.strip().encode('utf-8')).decode()

        print(colored('\nSending Message ...\n', 'yellow'))

        # Get receiver public key and certificate
        if not self.get_resources([payload['dst']]):
            return

        # Cipher sender and receiver message
        payload['msg'], nounce = self.secure.cipher_message_to_user(
            msg, self.secure.user_resources[payload['dst']]['pub_key'])

        payload['copy'], nounce_none = \
            self.secure.cipher_message_to_user(msg, None, nounce)

        data = self.send_payload(self.secure.encapsulate_secure_message(payload))
        data = self.secure.uncapsulate_secure_message(data)

        if 'error' in data:
            print(colored("ERROR: " + data['error'], 'red'))
        else:
            print(colored('\nMessage sent successfully!\n', 'green'))
            print(colored("Message ID: " + data['result'][0], 'green'))
            print(colored("Receipt ID: " + data['result'][1], 'green'))

    def receive_message(self):
        payload = {
            'type': 'recv'
        }

        while True:
            try:
                payload['id'] = int(input(colored("Message box's User ID: ", 'blue')))
                break
            except ValueError:
                print(colored("ERROR: Invalid User ID", 'red'))

        while True:
            try:
                payload['msg'] = str(input(colored("Message ID: ", 'blue')))
                break
            except ValueError:
                print(colored("ERROR: Invalid message ID", 'red'))

        print(colored('\nGetting Message ...\n', 'yellow'))

        data = self.send_payload(self.secure.encapsulate_secure_message(payload))
        data = self.secure.uncapsulate_secure_message(data)

        if 'error' in data:
            print(colored("ERROR: " + data['error'], 'red'))
        else:
            # Get sender public key and certificate
            # Get receiver public key and certificate
            sender_id = int(data['result'][0])
            if not self.get_resources([sender_id], data['resources']):
                print("error resource")
                return

            print(colored("Message Sender ID: %d" % sender_id, 'green'))

            # Decipher message
            message, nounce, cipher_suite = \
                self.secure.decipher_message_from_user(
                    data['result'][1],
                    self.secure.user_resources[sender_id]['certificate']
                )

            if 'error' in message:
                print(colored("ERROR: " + message['error'], 'red'))
                return

            message = base64.b64decode(message.encode()).decode('utf-8')

            print(colored("Message:\n" + message, 'green'))

            print(colored('\nSending receipt ...\n', 'yellow'))

            # Send receipt
            self.receipt_message(payload['msg'], message, nounce,
                                 int(data['result'][0]), cipher_suite)

    def receipt_message(self, message_id, message, nounce,
                        sender_id, cipher_suite):

        # Get receiver public key and certificate
        if not self.get_resources([sender_id]):
            print(colored("\nReceipt not sent!\n", 'red'))
            return

        # Create payload - not necessary to generate nounce
        payload = {
            'type': 'receipt',
            'id': self.user_id,
            'msg': message_id,
            'receipt': self.secure.generate_secure_receipt(
                message,
                nounce,
                self.secure.user_resources[sender_id]['pub_key'],
                cipher_suite
            ),
            'nounce': None
        }

        self.send_payload(self.secure.encapsulate_secure_message(payload),
                          response=False)

        print(colored('\nReceipt sent successfully!', 'green'))
        print(colored('\nWARNING: The server will not reply to this message, '
                      'so the receipt may not be accepted.\n', 'yellow'))

    def message_status(self):
        message = {
            'type': 'status'
        }

        while True:
            try:
                message['id'] = int(input(colored("Receipts box's User ID: ", 'blue')))
                break
            except ValueError:
                print(colored("ERROR: Invalid User ID", 'red'))

        while True:
            try:
                message['msg'] = str(input(colored("Message ID: ", 'blue')))
                break
            except ValueError:
                print(colored("ERROR: Invalid message ID", 'red'))

        print(colored('\nGetting status ...\n', 'yellow'))

        data = self.send_payload(self.secure.encapsulate_secure_message(message))
        data = self.secure.uncapsulate_secure_message(data)

        if 'error' in data:
            print(colored("ERROR: " + data['error'], 'red'))
        else:
            if len(data['result']['receipts']):
                # Get receiver public key and certificate
                dest_id = int(data['result']['receipts'][0]['id'])
                if not self.get_resources([dest_id], data['resources']):
                    return

                peer_cert = self.secure.user_resources[dest_id]['certificate']
            else:
                peer_cert = None

            info = self.secure.verify_secure_receipts(data['result'], peer_cert)

            if 'error' in info:
                print(colored("ERROR: " + info['error'], 'red'))
                return

            msg = base64.b64decode(info['msg'].encode()).decode('utf-8')
            print(colored("Message:\n" + msg, 'green'))
            print(colored("\nAll receipts: ", 'green'))
            for receipt in info['receipts']:
                print(colored(
                    "\tDate: " + time.ctime(float(receipt['date']) / 1000), 'green'))
                print(colored(
                    "\tReceipt sender ID: " + receipt['id'], 'green'))
                print(colored("\tHash(timestamp|message): " + receipt['receipt'], 'green'))
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
        print(colored("OPTIONS", 'blue'))
        print(colored("1 - [LIST] List all user client boxes", 'blue'))
        print(colored("2 - [NEW] List all new messages in a user's message box", 'blue'))
        print(colored("3 - [ALL] List all messages in a user's message box", 'blue'))
        print(colored("4 - [SEND] Send a new message", 'blue'))
        print(colored("5 - [RECV] Receive a message from a user's message box", 'blue'))
        print(colored("6 - [STATUS] Check the status of a previously sent message", 'blue'))
        print(colored("0 - [EXIT] Exit client", 'blue'))

        try:
            op = int(input(colored("Select an option: ", 'blue')))
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
            else:
                print(colored("Invalid option!", 'red'))
        except ValueError:
            print(colored("Invalid option!", 'red'))

    client.ss.close()
    return


if __name__ == "__main__":
    main()
