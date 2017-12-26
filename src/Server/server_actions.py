import logging
from src.Server.log import logger
from src.Server.server_registry import *
from src.Server.server_client import *
from src.Server.certificates import *
import json


class ServerActions:

    def __init__(self):

        self.messageTypes = {
            'all': self.processAll,
            'list': self.processList,
            'new': self.processNew,
            'send': self.processSend,
            'recv': self.processRecv,
            'create': self.processCreate,
            'receipt': self.processReceipt,
            'status': self.processStatus,
            'resource': self.processResource,
            'init': self.processInit
        }

        self.registry = ServerRegistry()
        self.certificates = X509Certificates(self.registry.users)

    def handleRequest(self, s, request, client, nounce):
        """Handle a request from a client socket.
        """
        try:
            logging.info("HANDLING message from %s: %r" %
                         (client, repr(request)))

            try:
                req = request
            except:
                logging.exception("Invalid message from client")
                return

            if not isinstance(req, dict):
                logger.log(logging.ERROR, "Invalid message format from client")
                return

            if 'type' not in req:
                logger.log(logging.ERROR, "Message has no TYPE field")
                return

            if req['type'] in self.messageTypes:
                self.messageTypes[req['type']](req, client, nounce)
            else:
                logger.log(logging.ERROR, "Invalid message type: " +
                    str(req['type']) + " Should be one of: " + str(
                    list(self.messageTypes.keys())))
                client.sendResult({"error": "unknown request"})

        except Exception as e:
            logging.exception("Could not handle request")

    def processCreate(self, data, client, nounce):
        logger.log(logging.DEBUG, "%s" % json.dumps(data))

        if 'uuid' not in list(data.keys()):
            logger.log(logging.ERROR, "No \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"}, nounce)
            return

        uuid = data['uuid']
        if not isinstance(uuid, int):
            logger.log(logging.ERROR,
                "No valid \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"}, nounce)
            return
        if self.registry.userExists(uuid):
            logger.log(logging.ERROR, "User already exists: " + json.dumps(data))
            client.sendResult({"error": "uuid already exists"}, nounce)
            return

        me = self.registry.addUser(data)
        print("(processCreate) Added new user:", self.registry.users)
        # TODO: Add security data to user profile
        client.sendResult({"result": me.id}, nounce)

    def processList(self, data, client, nounce):
        logger.log(logging.DEBUG, "%s" % json.dumps(data))

        user = 0  # 0 means all users
        userStr = "all users"
        if 'id' in list(data.keys()):
            user = int(data['id'])
            userStr = "user%d" % user

        logger.log(logging.DEBUG, "List %s" % userStr)

        userList = self.registry.listUsers(user)

        client.sendResult({"result": userList}, nounce)

    def processNew(self, data, client, nounce):
        logger.log(logging.DEBUG, "%s" % json.dumps(data))

        user = -1
        if 'id' in list(data.keys()):
            user = int(data['id'])

        if user < 0:
            logger.log(logging.ERROR,
                "No valid \"id\" field in \"new\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"}, nounce)
            return

        client.sendResult(
            {"result": self.registry.userNewMessages(user)}, nounce)

    def processAll(self, data, client, nounce):
        logger.log(logging.DEBUG, "%s" % json.dumps(data))

        user = -1
        if 'id' in list(data.keys()):
            user = int(data['id'])

        if user < 0:
            logger.log(logging.ERROR,
                "No valid \"id\" field in \"new\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"}, nounce)
            return

        client.sendResult({"result": [self.registry.userAllMessages(user),
                                      self.registry.userSentMessages(user)]},
                          nounce)

    def processSend(self, data, client, nounce):
        logger.log(logging.DEBUG, "%s" % json.dumps(data))

        if not set(data.keys()).issuperset(set({'src', 'dst', 'msg', 'copy'})):
            logger.log(logging.ERROR,
                "Badly formatted \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"}, nounce)

        srcId = int(data['src'])
        dstId = int(data['dst'])
        msg = str(data['msg'])
        copy = str(data['copy'])

        if not self.registry.userExists(srcId):
            logger.log(logging.ERROR,
                "Unknown source id for \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"}, nounce)
            return

        if not self.registry.userExists(dstId):
            logger.log(logging.ERROR,
                "Unknown destination id for \"send\" message: " + json.dumps(
                    data))
            client.sendResult({"error": "wrong parameters"}, nounce)
            return

        # Save message and copy

        response = self.registry.sendMessage(srcId, dstId, msg, copy)

        client.sendResult({"result": response}, nounce)

    def processRecv(self, data, client, nounce):
        logger.log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg'}).issubset(set(data.keys())):
            logger.log(logging.ERROR, "Badly formated \"recv\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"}, nounce)

        fromId = int(data['id'])
        msg = str(data['msg'])

        if not self.registry.userExists(fromId):
            logger.log(logging.ERROR,
                "Unknown source id for \"recv\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"}, nounce)
            return

        if not self.registry.messageExists(fromId, msg):
            logger.log(logging.ERROR,
                "Unknown source msg for \"recv\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"}, nounce)
            return

        # Read message

        response = self.registry.recvMessage(fromId, msg)

        client.sendResult({"result": response}, nounce)

    def processReceipt(self, data, client, nounce):
        logger.log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg', 'receipt'}).issubset(set(data.keys())):
            logger.log(logging.ERROR, "Badly formated \"receipt\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong request format"}, nounce)

        fromId = int(data["id"])
        msg = str(data['msg'])
        receipt = str(data['receipt'])

        if not self.registry.messageWasRed(str(fromId), msg):
            logger.log(logging.ERROR,
                "Unknown, or not yet red, message for \"receipt\" request " + json.dumps(
                    data))
            client.sendResult({"error": "wrong parameters"}, nounce)
            return

        self.registry.storeReceipt(fromId, msg, receipt)

    def processStatus(self, data, client, nounce):
        logger.log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg'}).issubset(set(data.keys())):
            logger.log(logging.ERROR, "Badly formated \"status\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"}, nounce)

        fromId = int(data['id'])
        msg = str(data["msg"])

        if not self.registry.copyExists(fromId, msg):
            logger.log(logging.ERROR,
                "Unknown message for \"status\" request: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"}, nounce)
            return

        response = self.registry.getReceipts(fromId, msg)
        client.sendResult({"result": response}, nounce)

    def processResource(self, data, client, nounce):
        logger.log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'ids'}).issubset(set(data.keys())):
            logger.log(logging.ERROR, "Badly formated \"status\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"}, nounce)

        result = []
        for user in data['ids']:
            pub_key = self.registry.users[user]['description']['secdata']['rsapubkey'] \
                if user in self.registry.users else None
            cc_pub_key = self.registry.users[user]['description']['secdata']['ccpubkey'] \
                if user in self.registry.users else None
            certificate = self.registry.users[user]['description']['secdata']['cccertificate'] \
                if user in self.registry.users else None
            cipher_spec = self.registry.users[user]['description']['secdata']['cipher_spec'] \
                if user in self.registry.users else None
            result += [
                {
                    'id': user,
                    'rsapubkey': pub_key,
                    'ccpubkey': cc_pub_key,
                    'cccertificate': certificate,
                    'cipher_spec': cipher_spec
                }
            ]
        client.sendResult({"result": result}, nounce)

    def processInit(self, data, client, nounce):
        logger.log(logging.DEBUG, "%s" % json.dumps(data))

        client.sendResult({"message": ""}, nounce)
