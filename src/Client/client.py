from socket import *
import json

ss = None
uuid = None

# Server address
HOST = ""   # All available interfaces
PORT = 8080  # The server port

BUFSIZE = 512 * 1024
TERMINATOR = "\n\n"
MAX_BUFSIZE = 64 * 1024


def create_user():
    if ss is None:
        print("Socket not established")
        return

    uuid = int(input("UUID: "))
    message = {
        'type': 'create',
        'uuid': uuid
        # security related fields
    }
    ss.send(json.dumps(message))
    data = json.loads(ss.recv(BUFSIZE))
    if 'error' in data:
        print("ERROR: " + data['error'])
    else:
        print("Your user id: " + str(data['result']))


def list_message_boxes():
    if ss is None:
        print("Socket not established")
        return

    message = {
        'type': 'list'
        # security related fields
    }

    id = input("User ID (optional): ")
    if len(id):
        message['id'] = int(id)

    ss.send(json.dumps(message))
    data = json.loads(ss.recv(BUFSIZE))
    if 'error' in data:
        print("ERROR: " + data['error'])
    else:
        print("User(s): ")
        for user in data['result']:
            print("\t" + user)


def list_all_new_messages():
    if ss is None:
        print("Socket not established")
        return

    message = {
        'type': 'new'
        # security related fields
    }

    id = input("User ID (optional): ")
    if len(id):
        message['id'] = int(id)

    ss.send(json.dumps(message))
    data = json.loads(ss.recv(BUFSIZE))
    if 'error' in data:
        print("ERROR: " + data['error'])
    else:
        print("New message(s): ")
        for message in data['result']:
            print("\t" + message)


def list_all_messages():
    if ss is None:
        print("Socket not established")
        return

    message = {
        'type': 'all'
        # security related fields
    }

    id = input("User ID (optional): ")
    if len(id):
        message['id'] = int(id)

    ss.send(json.dumps(message))
    data = json.loads(ss.recv(BUFSIZE))
    if 'error' in data:
        print("ERROR: " + data['error'])
    else:
        print("All received messages: ")
        for message in data['result'][0]:
            print("\t" + message)

        print("\n\nAll sent messages: ")
        for message in data['result'][1]:
            print("\t" + message)


def send_message():
    if ss is None:
        print("Socket not established")
        return

    message = {
        'type': 'send'
        # security related fields
    }

    id = input("Sender User ID: ")
    while not len(id):
        id = input("ERROR: You must insert a sender user id.\nSender User ID: ")
    message['src'] = int(id)

    id = input("Receiver User ID: ")
    while not len(id):
        id = input("ERROR: You must insert a sender receiver id.\nReceiver User ID: ")
    message['dst'] = int(id)

    ss.send(json.dumps(message))
    data = json.loads(ss.recv(BUFSIZE))
    if 'error' in data:
        print("ERROR: " + data['error'])
    else:
        print("All received messages: ")
        for message in data['result'][0]:
            print("\t" + message)

        print("\n\nAll sent messages: ")
        for message in data['result'][1]:
            print("\t" + message)

def main():
    """
    Show main menu.
    :return: 
    """
    ss = socket(AF_INET, SOCK_STREAM)
    ss.connect((HOST, 8080))

    uuid_read = input("UUID (optional): ")
    if len(uuid_read):
        uuid = int(uuid_read)

    while True:
        print("OPTIONS")
        print("1 - [CREATE] Create a new user message box")
        print("2 - [LIST] List all user client boxes")
        print("3 - [NEW] List all new message boxes")
        print("4 - [ALL] List all messages in a user's message box")
        print("5 - [SEND] Send a new message")
        print("6 - [RECV] Receive a message from a user's message box")
        print("7 - [STATUS] Check the status of a previously sent message")
        print("0 - [EXIT] Exit client")
        op = int(input("Select an option: "))

        if op == 0:
            break
        elif op == 1:
            create_user()
        elif op == 2:
            list_message_boxes()
        elif op == 3:
            create_user()
        elif op == 4:
            create_user()
        elif op == 5:
            create_user()
        elif op == 6:
            create_user()
        elif op == 7:
            create_user()

    ss.close()
    return

