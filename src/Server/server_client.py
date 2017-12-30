import logging
from log import logger
from server_secure import *
import json
import sys

TERMINATOR = "\r\n"
MAX_BUFSIZE = 64 * 1024

sys.tracebacklimit = 30


class Client:
    count = 0

    def __init__(self, socket, addr, registry, certs):
        self.socket = socket
        self.bufin = ""
        self.bufout = ""
        self.addr = addr
        self.id = None
        self.secure = ServerSecure(registry=registry, certs=certs)

        # TODO: Apply security constraints

    def __str__(self):
        """ Converts object into string.
        """
        return "Client(id=%r addr:%s)" % (self.id, str(self.addr))

    def asDict(self):
        return {'id': self.id}

    def parseReqs(self, data):
        """Parse a chunk of data from this client.
        Return any complete requests in a list.
        Leave incomplete requests in the buffer.
        This is called whenever data is available from client socket."""

        if len(self.bufin) + len(data) > MAX_BUFSIZE:
            logger.log(logging.ERROR, "Client (%s) buffer exceeds MAX BUFSIZE. %d > %d" %
                (self, len(self.bufin) + len(data), MAX_BUFSIZE))
            self.bufin = ""

        self.bufin += data
        reqs = self.bufin.split(TERMINATOR)
        self.bufin = reqs[-1]
        return reqs[:-1]

    def sendResult(self, obj, nounce):
        """Send an object to this client.
        """
        try:
            self.bufout += json.dumps(self.secure.encapsulate_secure_message(
                json.dumps(obj), nounce)) + "\n\n"
        except:
            # It should never happen! And not be reported to the client!
            logging.exception("Client.send(%s)" % self)

    def close(self):
        """Shuts down and closes this client's socket.
        Will log error if called on a client with closed socket.
        Never fails.
        """
        logger.log(logging.INFO, "Client.close(%s)" % self)
        try:
            self.socket.close()
        except:
            logging.exception("Client.close(%s)" % self)
