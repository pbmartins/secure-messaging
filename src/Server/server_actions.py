import logging
from log import logger
from server_registry import *
from server_client import *
from certificates import *
import json
import re


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
            'init': self.processInit,
            'error': self.processError
        }

        self.registry = ServerRegistry()
        self.certificates = X509Certificates(self.registry.users)

    def handleRequest(self, s, request, client, nonce):
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
                self.messageTypes[req['type']](req, client, nonce)
            else:
                logger.log(logging.ERROR, "Invalid message type: " +
                    str(req['type']) + " Should be one of: " + str(
                    list(self.messageTypes.keys())))
                client.sendResult({"error": "unknown request"})

        except Exception as e:
            logging.exception("Could not handle request")

    def processCreate(self, data, client, nonce):
        logger.log(logging.DEBUG, "%s" % json.dumps(data))

        if 'uuid' not in list(data.keys()):
            logger.log(logging.ERROR, "No \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"}, nonce)
            return

        if not set(data.keys()).issuperset(set({'secdata', 'signature'})):
            logger.log(logging.ERROR,
                       "Badly formatted \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"}, nonce)

        uuid = data['uuid']
        if not isinstance(uuid, int):
            logger.log(logging.ERROR,
                "No valid \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"}, nonce)
            return

        if self.registry.userExists(uuid):
            logger.log(logging.ERROR, "User already exists: " + json.dumps(data))
            client.sendResult({"error": "uuid already exists"}, nonce)
            return

        me = self.registry.addUser(data)

        client.sendResult({"result": me.id}, nonce)

    def processList(self, data, client, nonce):
        logger.log(logging.DEBUG, "%s" % json.dumps(data))

        user = 0  # 0 means all users
        userStr = "all users"
        if 'id' in list(data.keys()):
            user = int(data['id'])
            userStr = "user%d" % user

        logger.log(logging.DEBUG, "List %s" % userStr)

        userList = self.registry.listUsers(user)

        client.sendResult({"result": userList}, nonce)

    def processNew(self, data, client, nonce):
        logger.log(logging.DEBUG, "%s" % json.dumps(data))

        user = -1
        if 'id' in list(data.keys()):
            user = int(data['id'])

        if user < 0:
            logger.log(logging.ERROR,
                "No valid \"id\" field in \"new\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"}, nonce)
            return

        client.sendResult(
            {"result": self.registry.userNewMessages(user)}, nonce)

    def processAll(self, data, client, nonce):
        logger.log(logging.DEBUG, "%s" % json.dumps(data))

        user = -1
        if 'id' in list(data.keys()):
            user = int(data['id'])

        if user < 0:
            logger.log(logging.ERROR,
                "No valid \"id\" field in \"new\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"}, nonce)
            return

        client.sendResult({"result": [self.registry.userAllMessages(user),
                                      self.registry.userSentMessages(user)]},
                          nonce)

    def processSend(self, data, client, nonce):
        logger.log(logging.DEBUG, "%s" % json.dumps(data))

        if not set(data.keys()).issuperset(set({'src', 'dst', 'msg', 'copy'})):
            logger.log(logging.ERROR,
                "Badly formatted \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"}, nonce)

        srcId = int(data['src'])
        dstId = int(data['dst'])
        msg = str(data['msg'])
        copy = str(data['copy'])

        if not self.registry.userExists(srcId):
            logger.log(logging.ERROR,
                "Unknown source id for \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"}, nonce)
            return

        if self.registry.getUser(client.secure.uuid).id != srcId:
            logger.log(
                logging.ERROR,
                "Source id different from client id for \"send\" message: "
                + json.dumps(data)
            )
            client.sendResult({"error": "wrong parameters"}, nonce)
            return

        if not self.registry.userExists(dstId):
            logger.log(logging.ERROR,
                "Unknown destination id for \"send\" message: " + json.dumps(
                    data))
            client.sendResult({"error": "wrong parameters"}, nonce)
            return

        # Save message and copy
        response = self.registry.sendMessage(srcId, dstId, msg, copy)

        client.sendResult({"result": response}, nonce)

    def processRecv(self, data, client, nonce):
        logger.log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg'}).issubset(set(data.keys())):
            logger.log(logging.ERROR, "Badly formated \"recv\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"}, nonce)

        fromId = int(data['id'])
        msg = str(data['msg'])

        if not self.registry.userExists(fromId):
            logger.log(logging.ERROR,
                "Unknown source id for \"recv\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"}, nonce)
            return

        if not self.registry.messageExists(fromId, msg):
            logger.log(logging.ERROR,
                "Unknown source msg for \"recv\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"}, nonce)
            return

        # Read message

        response = self.registry.recvMessage(fromId, msg)
        sender_id = int(response[0])

        client.sendResult(
            {
                "result": response,
                "resources": {'result': [self.get_user_resources(sender_id)]}
            },
            nonce
        )

    def processReceipt(self, data, client, nonce):
        logger.log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg', 'receipt'}).issubset(set(data.keys())):
            logger.log(logging.ERROR, "Badly formated \"receipt\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong request format"}, nonce)

        fromId = int(data["id"])
        msg = str(data['msg'])
        receipt = str(data['receipt'])

        if self.registry.getUser(client.secure.uuid).id != fromId:
            logger.log(
                logging.ERROR,
                "Source id different from client id for \"receipt\" request: "
                + json.dumps(data)
            )
            return

        if not self.registry.messageWasRed(str(fromId), msg):
            logger.log(logging.ERROR,
                "Unknown, or not yet red, message for \"receipt\" request " + json.dumps(
                    data))
            client.sendResult({"error": "wrong parameters"}, nonce)
            return

        self.registry.storeReceipt(fromId, msg, receipt)

    def processStatus(self, data, client, nonce):
        logger.log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg'}).issubset(set(data.keys())):
            logger.log(logging.ERROR, "Badly formated \"status\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"}, nonce)

        fromId = int(data['id'])
        msg = str(data["msg"])

        if not self.registry.copyExists(fromId, msg):
            logger.log(logging.ERROR,
                "Unknown message for \"status\" request: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"}, nonce)
            return

        response = self.registry.getReceipts(fromId, msg)

        pattern = "([0-9]+)_[0-9]+"
        matches = re.match(pattern, msg)
        dest_id = int(matches.group(1))
        print("READER_ID:", dest_id)
        client.sendResult(
            {
                "result": response,
                "resources": {'result': [self.get_user_resources(dest_id)]}
            },
            nonce
        )

    def processResource(self, data, client, nonce):
        logger.log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'ids'}).issubset(set(data.keys())):
            logger.log(logging.ERROR, "Badly formated \"status\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"}, nonce)

        result = []
        for user in data['ids']:
            result += [self.get_user_resources(user)]

        client.sendResult({"result": result}, nonce)

    def processInit(self, data, client, nonce):
        logger.log(logging.DEBUG, "%s" % json.dumps(data))

        me = self.registry.getUser(data['uuid'])
        user_id = me.id if me is not None else ''
        client.sendResult({"result": user_id}, nonce)

    def processError(self, data, client, nonce):
        logger.log(logging.DEBUG, "%s" % json.dumps(data))

        client.sendResult(data, nonce)

    def get_user_resources(self, user):
        sec_data = self.registry.users[user]['description']['secdata'] \
            if user in self.registry.users else None

        signature = self.registry.users[user]['description']['signature'] \
            if user in self.registry.users else None

        result = {
            'id': user,
            'secdata': sec_data,
            'signature': signature
        }

        return result
