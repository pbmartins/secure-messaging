from socket import *
import json
import base64

ss = None
uuid = None

# Server address
HOST = ""   # All available interfaces
PORT = 8080  # The server port

BUFSIZE = 512 * 1024
TERMINATOR = "\n\n"
MAX_BUFSIZE = 64 * 1024


def create_user():
    global ss
    global uuid

    if ss is None:
        print("Socket not established")
        return

    if uuid is None:
        print("Cannot create a message box without an UUID")
        return

    message = {
        'type': 'create',
        'uuid': uuid
        # security related fields
    }

    ss.send(json.dumps(message)[:BUFSIZE].encode('utf-8')
            + '\r\n'.encode('utf-8'))
    data = json.loads(ss.recv(BUFSIZE).decode('utf-8').split(TERMINATOR)[0])

    if 'error' in data:
        print("ERROR: " + data['error'])
    else:
        print("Your user id: " + str(data['result']))


def list_message_boxes():
    global ss

    if ss is None:
        print("Socket not established")
        return

    message = {
        'type': 'list'
        # security related fields
    }

    user_id = input("User ID (optional): ")
    if len(user_id):
        message['id'] = int(user_id)

    ss.send(json.dumps(message)[:BUFSIZE].encode('utf-8')
            + '\r\n'.encode('utf-8'))
    data = json.loads(ss.recv(BUFSIZE).decode('utf-8').split(TERMINATOR)[0])

    if 'error' in data:
        print("ERROR: " + data['error'])
    else:
        print("User UUID(s): ")
        for i in range(0, len(data['result'])):
            print(str.format("\tID: {:d} - UUID: {:d}",
                             i + 1, data['result'][i]['uuid']))


def list_all_new_messages():
    global ss

    if ss is None:
        print("Socket not established")
        return

    message = {
        'type': 'new'
        # security related fields
    }

    while True:
        try:
            message['id'] = int(input("User ID: "))
            break
        except ValueError:
            print("ERROR: Invalid User ID")

    ss.send(json.dumps(message)[:BUFSIZE].encode('utf-8')
            + '\r\n'.encode('utf-8'))
    data = json.loads(ss.recv(BUFSIZE).decode('utf-8').split(TERMINATOR)[0])
    if 'error' in data:
        print("ERROR: " + data['error'])
    else:
        print("New message(s): ")
        for message in data['result']:
            print("\t" + message)


def list_all_messages():
    global ss

    if ss is None:
        print("Socket not established")
        return

    message = {
        'type': 'all'
        # security related fields
    }

    while True:
        try:
            message['id'] = int(input("User ID: "))
            break
        except ValueError:
            print("ERROR: Invalid User ID")

    ss.send(json.dumps(message)[:BUFSIZE].encode('utf-8')
            + '\r\n'.encode('utf-8'))
    data = json.loads(ss.recv(BUFSIZE).decode('utf-8').split(TERMINATOR)[0])
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
    global ss

    if ss is None:
        print("Socket not established")
        return

    message = {
        'type': 'send'
        # security related fields
    }

    while True:
        try:
            message['src'] = int(input("Sender User ID: "))
            break
        except ValueError:
            print("ERROR: Invalid User ID")

    while True:
        try:
            message['dst'] = int(input("Receiver User ID: "))
            break
        except ValueError:
            print("ERROR: Invalid User ID")

    # Read message
    print("Message (two line breaks to send it):")
    message['msg'] = ""
    line = ""
    while True:
        last_line = line
        line = input()
        message['msg'] += line + "\n"
        if not len(line) and not len(last_line):
            break

    message['msg'] = json.dumps(message['msg'])
    message['copy'] = message['msg']

    ss.send(json.dumps(message)[:BUFSIZE].encode('utf-8')
            + '\r\n'.encode('utf-8'))
    data = json.loads(ss.recv(BUFSIZE).decode('utf-8').split(TERMINATOR)[0])
    if 'error' in data:
        print("ERROR: " + data['error'])
    else:
        print("Message ID: " + data['result'][0])
        print("Receipt ID: " + data['result'][1])


def receive_message():
    global ss

    if ss is None:
        print("Socket not established")
        return

    message = {
        'type': 'recv'
        # security related fields
    }

    while True:
        try:
            message['id'] = int(input("Message box's User ID: "))
            break
        except ValueError:
            print("ERROR: Invalid User ID")

    while True:
        try:
            message['msg'] = str(input("Message ID: "))
            break
        except ValueError:
            print("ERROR: Invalid message ID")

    ss.send(json.dumps(message)[:BUFSIZE].encode('utf-8')
            + '\r\n'.encode('utf-8'))
    data = json.loads(ss.recv(BUFSIZE).decode('utf-8').split(TERMINATOR)[0])
    if 'error' in data:
        print("ERROR: " + data['error'])
    else:
        print("Message Sender ID: " + data['result'][0])
        print("Message: " + data['result'][1])


def receipt_message():
    global ss

    if ss is None:
        print("Socket not established")
        return

    message = {
        'type': 'receipt'
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

    # TODO :
    # receipt field contains a signature over the plaintext message received,
    # calculated with the same credentials that the user uses to authenticate mes-
    # sages to other users.
    message['receipt'] = ""

    ss.send(json.dumps(message)[:BUFSIZE].encode('utf-8')
            + '\r\n'.encode('utf-8'))


def message_status():
    global ss

    if ss is None:
        print("Socket not established")
        return

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

    ss.send(json.dumps(message)[:BUFSIZE].encode('utf-8')
            + '\r\n'.encode('utf-8'))
    data = json.loads(ss.recv(BUFSIZE).decode('utf-8').split(TERMINATOR)[0])

    if 'error' in data:
        print("ERROR: " + data['error'])
    else:
        print("Message: " + data['result']['msg'])
        print("\nAll receipts: ")
        for receipt in data['result']['receipts']:
            print("\tDate: " + receipt['date'])
            print("\tReceipt sender ID: " + receipt['id'])
            print("\tReceipt: " + receipt['receipt'])
            print("")


def main():
    """
    Show main menu.
    :return: 
    """

    global ss
    global uuid

    ss = socket(AF_INET, SOCK_STREAM)
    ss.connect((HOST, 8080))

    uuid_read = input("UUID (optional): ")
    if len(uuid_read):
        uuid = int(uuid_read)

    print(uuid)

    while True:
        print("")
        print("OPTIONS")
        print("1 - [CREATE] Create a new user message box")
        print("2 - [LIST] List all user client boxes")
        print("3 - [NEW] List all new messages in a user's message box")
        print("4 - [ALL] List all messages in a user's message box")
        print("5 - [SEND] Send a new message")
        print("6 - [RECV] Receive a message from a user's message box")
        print("7 - [RECEIPT] Receipt sent after receiving and validating a message")
        print("8 - [STATUS] Check the status of a previously sent message")
        print("0 - [EXIT] Exit client")
        op = int(input("Select an option: "))
        print("")

        if op == 0:
            break
        elif op == 1:
            create_user()
        elif op == 2:
            list_message_boxes()
        elif op == 3:
            list_all_new_messages()
        elif op == 4:
            list_all_messages()
        elif op == 5:
            send_message()
        elif op == 6:
            receive_message()
        elif op == 7:
            receipt_message()
        elif op == 8:
            message_status()

    ss.close()
    return


if __name__ == "__main__":
    main()
