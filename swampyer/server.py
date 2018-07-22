import re
import threading
import sys
import base64
import hashlib
import random

from .messages import *
from .utils import logger
from .exceptions import *

from SimpleWebSocketServer.SimpleWebSocketServer import WebSocket,\
                                  SimpleWebSocketServer,\
                                  HTTPRequest, \
                                  BINARY, CLOSE, GUID_STR,\
                                  VER

HANDSHAKE_STR = (
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Upgrade: WebSocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Accept: %(acceptstr)s\r\n"
    "Sec-Websocket-Protocol: wamp.2.json\r\n"
    "\r\n"
)

STATE_DISCONNECTED = 0
STATE_CONNECTING = 1
STATE_WEBSOCKET_CONNECTED = 3
STATE_AUTHENTICATING = 4
STATE_CONNECTED = 2

clients = []
class WAMPWebSocket(WebSocket):
    def __init__(self,session_id,*args,**kwargs):
        super(WAMPWebSocket,self).__init__(*args,**kwargs)
        self.session_id = session_id
        self.state = STATE_CONNECTING

    def _handleData(self):
        # do the HTTP header and handshake
        if self.handshaked is False:

            data = self.client.recv(self.headertoread)
            if not data:
                raise Exception('remote socket closed')

            else:
                # accumulate
                self.headerbuffer.extend(data)

                if len(self.headerbuffer) >= self.maxheader:
                    raise Exception('header exceeded allowable size')

                # indicates end of HTTP header
                if b'\r\n\r\n' in self.headerbuffer:
                    self.request = HTTPRequest(self.headerbuffer)

                    # Does this match the required path?
                    if self.request.path != self.server.path:
                        self.sendq.append(
                          (
                              CLOSE,ERROR_MESSAGE.encode('ascii')
                          )
                        )
                        return

                    # handshake rfc 6455
                    try:
                        key = self.request.headers['Sec-WebSocket-Key']
                        k = key.encode('ascii') + GUID_STR.encode('ascii')
                        k_s = base64.b64encode(hashlib.sha1(k).digest()).decode('ascii')
                        hStr = HANDSHAKE_STR % {'acceptstr': k_s}

                        self.sendq.append((BINARY, hStr.encode('ascii')))
                        self.handshaked = True
                        self.handleConnected()
                    except Exception as e:
                        raise Exception('handshake failed: %s', str(e))

        # else do normal data
        else:
            data = self.client.recv(16384)
            if not data:
                raise Exception("remote socket closed")

            if VER >= 3:
                for d in data:
                    self._parseMessage(d)
            else:
                for d in data:
                    self._parseMessage(ord(d))

    def dispatch_to_awaiting(self,result):
        """ Send data ato the appropriate queues
        """

        print "GOT A HELLO!"
        print "ABOUT TO SND REPLY", result, self.state
        # If we are awaiting to login, then we might also get
        # an abort message. Handle that here....
        """
        if self.state == STATE_AUTHENTICATING:
            # If the authentication message is something unexpected,
            # we'll just ignore it for now
            if result == WAMP_ABORT \
               or result == WAMP_WELCOME \
               or result == WAMP_GOODBYE:
                self._welcome_queue.put(result)
            return

        # If we aren't connected yet, don't do anything
        if self.state != STATE_CONNECTED:
            return

        """

        try:
            self.send_message(result)
        except Exception as ex:
            print ex
            raise Exception("Response does not have a request id. Do not know who to send data to. Data: {} ".format(result.dump()))


    def handle_hello(self, hello):
        """ A new customer!
        """

        # We only trigger authentications if the server has users
        # setup.
        if self.server.users and hello.details['authmethods']:
            self.state = STATE_AUTHENTICATING
            challenge = self.server.auth_method_prepare(self,hello)
            if not challenge:
                return ERROR(
                        request_code = WAMP_HELLO,
                        request_id = None,
                        details = {},
                        error = 'None of the authmethods are support. We only support ticket ',
                        args = [],
                    )
            return self.dispatch_to_awaiting(challenge)

        self.state = STATE_CONNECTED
        details = self.server.auth_details(self,'anonymous','anonymous')

        self.dispatch_to_awaiting(WELCOME(
                    session_id=self.session_id,
                    details=details
                ))

    def handle_authenticate(self, response):
        """ When a client responds to a challenge request
        """
        result = self.server.auth_method_authenticate(self,response)
        if result:
            self.state = STATE_CONNECTED
        self.dispatch_to_awaiting(result)

    def handle_error(self, error):
        """ OOops! An error occurred
        """
        self.dispatch_to_awaiting(error)

    def handle_unknown(self, message):
        """ We don't know what to do with this. So we'll send it
            into the queue just in case someone wants to do something
            with it but we'll just blackhole it.
        """
        print "Unknown message:", message.dump()
        self.dispatch_to_awaiting(message)

    def send_message(self,message):
        """ Send awamp message to the server. We don't wait
            for a response here. Just fire out a message
        """
        if self.state == STATE_DISCONNECTED:
            raise Exception("WAMP is currently disconnected!")
        message = message.as_str()
        logger.debug("SND>: {}".format(message))
        self.sendMessage(message)

    def handleMessage(self):
        """ Handles incoming packets
        """

        try:
            logger.debug("<RCV: {}".format(self.data))
            message = WampMessage.loads(self.data)
            logger.debug("<RCV: {}".format(message.dump()))
            try:
                code_name = message.code_name.lower()
                handler_name = "handle_"+code_name
                handler_function = getattr(self,handler_name)
                handler_function(message)
            except AttributeError as ex:
                print "ERROR:", ex
                self.handle_unknown(message)
        except Exception as ex:
            # FIXME: Needs more granular exception handling
            import traceback
            traceback.print_exc()
            print "OOPS:", ex
            raise


        print "MESSAGE", message.dump()

        """
        for client in clients:
            if client != self:
                client.sendMessage(self.address[0] + u' - ' + self.data)
        """

    def handleConnected(self):
        print (self.address, 'connected')
        clients.append(self)

    def handleClose(self):
        clients.remove(self)

class WAMPServer(SimpleWebSocketServer):
    def __init__(
                self,
                url='ws://localhost:8282/ws',
                cert=None,
                key=None,
                version=None,
                uri_base='',
                realm='realm1',
                selectInterval=0.01,
                users=None,
                ):
        self.url = url
        self.cert = cert
        self.key = key
        self.version = version
        self.uri_base = uri_base
        self.realm = realm
        self.wsserver = None

        # Parse out the path so we can sort out stuff like
        # SSL and all that.
        m = re.search('^(ws+)://([\w\.]+)(?::(\d+))?(/?.*)$',
                              url,flags=re.IGNORECASE)
        if not m:
            raise SwampyException("Could not parse URL %s",url)
        (protocol, host, port, path) = m.groups()

        self.protocol = protocol.lower()
        self.ssl = self.protocol == 'wss'
        self.host = host.lower()
        self.port = int(port)
        self.path = path
        self.rng = random.SystemRandom()

        # For registrations of callbacks
        self.registrations = []

        # if users is none, no access credentials required
        self.users = users

        # Now we can initialize the parent object
        super(WAMPServer,self).__init__(
                self.host, self.port,
                WAMPWebSocket,
                selectInterval
            )


    def rand(self):
        return self.rng.randint(0,sys.maxsize)

    def _decorateSocket(self, sock):
        if not self.ssl:
            return sock
        sslsock = self.context.wrap_socket(sock, server_side=True)
        return sslsock

    def _constructWebSocket(self, sock, address):
        try:
            ws = self.websocketclass(
                        self.rand(), # session id
                        self,
                        sock,
                        address)
            ws.usingssl = True
            return ws
        except Exception as ex:
            print "Couldn't create websocket:", ex
            raise

    def start(self):
        """ Currently an alias. Might do more in the future?
        """
        def worker(self):
            self.serveforever()
        self.main_thread = threading.Thread(target=worker,args=(self,))
        self.main_thread.daemon = True
        self.main_thread.start()

    def auth_details(self,client,authid,authrole):
        return {
            u'authid': authid,
            u'authmethod': u'ticket',
            u'authprovider': u'dynamic',
            u'authrole': u'anonymous',
            u'realm': self.realm,
            u'roles': {u'broker': {u'features': {
                                                 u'event_retention': False,
                                                 u'pattern_based_subscription': False,
                                                 u'payload_encryption_cryptobox': False,
                                                 u'payload_transparency': False,
                                                 u'publisher_exclusion': False,
                                                 u'publisher_identification': False,
                                                 u'session_meta_api': False,
                                                 u'subscriber_blackwhite_listing': False,
                                                 u'subscription_meta_api': False,
                                                 u'subscription_revocation': False
                                                 }},
                       u'dealer': {u'features': {
                                                 u'call_canceling': False,
                                                 u'caller_identification': False,
                                                 u'pattern_based_registration': False,
                                                 u'payload_encryption_cryptobox': False,
                                                 u'payload_transparency': False,
                                                 u'progressive_call_results': False,
                                                 u'registration_meta_api': False,
                                                 u'registration_revocation': False,
                                                 u'session_meta_api': False,
                                                 u'shared_registration': False,
                                                 u'testament_meta_api': False
                                                 }}},
            u'x_cb_node_id': None
        }


    def generate_request_id(self):
        """ We cheat, we just use the millisecond timestamp for the request
        """
        return int(round(time.time() * 1000))

    def auth_method_prepare(self,client,message):
        """ Returns the auth method the client should use for
            authentication
        """
        if not self.users:
            return

        if 'ticket' not in message.details.get('authmethods',[]):
            return ERROR(
                        request_code = WAMP_HELLO,
                        request_id = None,
                        details = {},
                        error = 'Unable to authenticate',
                        args = [],
                    )

        client.auth_method = 'ticket'
        client.authid = message.details['authid']
        return CHALLENGE(
                        auth_method='ticket',
                        extra={}
                    )

    def auth_method_authenticate(self,client,response):
        """ Does the actual work of authenticating the user
        """
        if client.auth_method != 'ticket':
            return ERROR(
                request_code = WAMP_AUTHENTICATE,
                request_id = None,
                details = {},
                error = 'Non ticket based authentication not supported',
                args = [],
            )

        authid = client.authid
        generic_auth_error = ERROR(
                                request_code = WAMP_AUTHENTICATE,
                                request_id = None,
                                details = {},
                                error = 'Unable to authenticate',
                                args = [],
                            )
        if authid not in self.users:
            return generic_auth_error

        user_data = self.users[authid]
        password = user_data.get('password',None)
        if not password:
            return generic_auth_error

        if response.signature != password:
            return generic_auth_error

        # Okay the person is why they say they are.
        client.user_data = user_data
        details = self.auth_details(
                        self.client,
                        authid,
                        authid
                    )

        return WELCOME(
            session_id=client.session_id,
            details=details
        )

    def call(self,uri,*args,**kwargs):
        full_uri = self.uri_base + '.' + uri
        for reg in self.registrations:
            if reg['uri'] == full_uri:
                result = reg['callback'](*args,**kwargs)
                return result
        return ERROR(
                    request_code = WAMP_CALL
                    request_id = None,
                    details = {},
                    error = 'None of the authmethods are support. We only support ticket ',
                    args = [],
                )

    def register(self,uri,callback,options=None):
        full_uri = self.uri_base + '.' + uri
        registration_id = self.rand()
        new_reg = {
            'registration_id': registration_id,
            'uri': full_uri,
            'callback': callback
            'options': options
        }
        self.registrations.append(new_reg)

    def publish(self,uri,message):
        id = self.generate_request_id()
        topic = self.uri_base + '.' + topic
