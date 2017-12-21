# encoding: utf-8
#
# jpbarraca@ua.pt
# jmr@ua.pt 2016

# vim setings:
# :set expandtab ts=4

from socket import *
from select import *
import json
import sys
import time
import logging
from src.Server.log import *
from src.Server.server_client import *
from src.Server.server_registry import *
from src.Server.server_actions import *
from src.Client.cipher_utils import *
from src.Server.certificates import *

# Server address
HOST = ""   # All available interfaces
PORT = 8080  # The server port

BUFSIZE = 512 * 1024
TERMINATOR = "\n\n"
MAX_BUFSIZE = 64 * 1024


class Server:

    def __init__(self, host, port):
        self.ss = socket(AF_INET, SOCK_STREAM)  # the server socket (IP \ TCP)
        self.ss.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.ss.bind((host, port))
        self.ss.listen(10)
        log(logging.INFO, "Secure IM server listening on %s" %
            str(self.ss.getsockname()))

        self.registry = ServerRegistry()
        self.server_actions = ServerActions()
        self.certificates = X509Certificates(self.registry.users)

        # clients to manage (indexed by socket and by name):
        self.clients = {}       # clients (key is socket)

    def stop(self):
        """ Stops the server closing all sockets
        """
        log(logging.INFO, "Stopping Server")
        try:
            self.ss.close()
        except:
            logging.exception("Server.stop")

        for csock in self.clients:
            try:
                self.clients[csock].close()  # Client.close!
            except:
                # this should not happen since close is protected...
                logging.exception("clients[csock].close")

        # If we delClient instead, the following would be unnecessary...
        self.clients.clear()

    def addClient(self, csock, addr):
        """Add a client connecting in csock."""
        if csock in self.clients:
            log(logging.ERROR, "Client NOT Added: %s already exists" %
                self.clients[csock])
            return

        client = Client(csock, addr)
        self.clients[client.socket] = client
        log(logging.DEBUG, "Client added: %s" % client)

    def delClient(self, csock):
        """Delete a client connected in csock."""
        if csock not in self.clients:
            log(logging.ERROR, "Client NOT deleted: %s not found" %
                self.clients[csock])
            return

        client = self.clients[csock]

        del self.clients[client.socket]
        client.close()
        log(logging.DEBUG, "Client deleted: %s" % client)

    def accept(self):
        """Accept a new connection.
        """
        try:
            csock, addr = self.ss.accept()
            self.addClient(csock, addr)
        except:
            logging.exception("Could not accept client")

    def flushin(self, s):
        """Read a chunk of data from this client.
        Enqueue any complete requests.
        Leave incomplete requests in buffer.
        This is called whenever data is available from client socket.
        """
        client = self.clients[s]
        data = None
        try:
            data = s.recv(BUFSIZE).decode('utf-8')
            log(logging.DEBUG,
                "Received data from %s. Message:\n%r" % (client, data))
        except:
            logging.exception("flushin: recv(%s)" % client)
            self.delClient(s)
        else:
            if len(data) > 0:
                reqs = client.parseReqs(data)
                for req in reqs:
                    self.server_actions.handleRequest(s, req, self.clients[s])
            else:
                self.delClient(s)

    def flushout(self, s):
        """Write a chunk of data to client.
        This is called whenever client socket is ready to transmit data."""
        if s not in self.clients:
            return

        client = self.clients[s]
        try:
            sent = client.socket.send(client.bufout[:BUFSIZE].encode('utf-8'))
            log(logging.DEBUG, "Sent %d bytes to %s. Message:\n%r" %
                (sent, client, client.bufout[:sent]))
            # leave remaining to be sent later
            client.bufout = client.bufout[sent:]
        except:
            logging.exception("flushout: send(%s)", client)
            # logging.error("Cannot write to client %s. Closing", client)
            self.delClient(client.socket)

    def loop(self):
        while True:
            # sockets to select for reading: (the server socket + every open
            # client connection)
            rlist = [self.ss] + list(self.clients.keys())

            # sockets to select for writing: (those that have something in
            # bufout)
            wlist = [sock for sock in self.clients if len(
                self.clients[sock].bufout) > 0]

            (rl, wl, xl) = select(rlist, wlist, rlist)

            # Deal with incoming data:
            for s in rl:
                if s is self.ss:
                    self.accept()
                elif s in self.clients:
                    self.flushin(s)
                else:
                    log(logging.ERROR,
                        "Incoming, but %s not in clients anymore" % s)

            # Deal with outgoing data:
            for s in wl:
                if s in self.clients:
                    self.flushout(s)
                else:
                    log(logging.ERROR,
                        "Outgoing, but %s not in clients anymore" % s)

            for s in xl:
                log(logging.ERROR, "EXCEPTION in %s. Closing" % s)
                self.delClient(s)


serv = None

if __name__ == "__main__":
    global serv
    if len(sys.argv) > 1:
        PORT = int(sys.argv[1])

    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format=
        '%(asctime)s - %(levelname)s - %(message)s')

    while True:
        try:
            log(logging.INFO, "Starting Secure IM Server v1.0")
            serv = Server(HOST, PORT)
            serv.loop()
        except KeyboardInterrupt:
            serv.stop()
            try:
                log(logging.INFO, "Press CTRL-C again within 2 sec to quit")
                time.sleep(2)
            except KeyboardInterrupt:
                log(logging.INFO, "CTRL-C pressed twice: Quitting!")
                break
        except:
            logging.exception("Server ERROR")
            if serv is not (None):
                serv.stop()
            time.sleep(10)
