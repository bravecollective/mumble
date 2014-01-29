# encoding: utf-8

# from __future__ import unicode_literals

import sys
import time
import datetime
import tempfile
import Ice
import IcePy
from threading import Timer

from brave.mumble.auth.model import Ticket

Ice.loadSlice(b'', [b'-I' + (Ice.getSliceDir() or b'/usr/local/share/Ice-3.5/slice/'), b'Murmur.ice'])
import Murmur


log = __import__('logging').getLogger(__name__)



AUTH_FAIL = (-1, None, None)
NO_INFO = (False, {})


class ServerAuthenticator(Murmur.ServerUpdatingAuthenticator):
    """MongoDB-backed Mumble authentication agent.
    
    Murmur ICE reference: http://mumble.sourceforge.net/slice/Murmur.html
    """
    
    # TODO: Factor out all the "registered__exists=True, registered__not=None" clones.
    
    def __init__(self, server, meta):
        self.server = server  # TODO: No super()?!
        self.meta = meta
    
    def authenticate(self, name, pw, certlist, certhash, strong, current=None):
        """Authenticate a Mumble user.
        
        * certlist: the X509 certificate chain of the user's certificate
        
        Returns a 3-tuple of user_id, user_name, groups.
        """
        
        log.info('authenticate "%s" %s %r', name, certhash, strong)
        
        # Look up the user.
        try:
            user = Ticket.objects.get(character__name=name).only('password', 'alliance__id', 'character__id')
        except Ticket.NotFound:
            log.warn('notfound "%s"', name)
            return AUTH_FAIL
        
        if not user.password.check(user.password, pw):
            log.warn('fail "%s"', name)
            return AUTH_FAIL
        
        # TODO: Refresh the ticket details from Core to ensure it's valid and we have the latest tags.
        
        # Define the registration date if one has not been set.
        Ticket.objects(character__name=name, registered=None).update(set__registered=datetime.datetime.utcnow())
        
        # Check for BRAVE membership.
        # TODO: Don't hard-code this, check for the 'mumble' or 'member' tags.
        if not user.alliance.id or user.alliance.id != 99003214:
            log.warn('thirdparty "%s"', name)
            return AUTH_FAIL
        
        # TODO: Do we have to force user registration here?
        # self.server.registerUser(info)
        
        log.debug('success "%s"', name)
        return (user.character.id, name, user.tags + (['member'] if 'member' not in user.tags else []))  # TODO: Fixme when auth provides tags.
    
    def getInfo(self, id, current=None):
        return false  # for now, let's pass through
        
        log.debug('getInfo %d', id)
        
        try:
            seen, name, comment = Ticket.objects(character__id=id, registered__exists=True, registered__not=None).scalar('seen', 'character__name', 'comment').first()
        except TypeError:
            return NO_INFO
        
        if name is None: return NO_INFO
        
        return True, {
                # Murmur.UserInfo.UserLastActive: seen,  # TODO: Verify the format this needs to be in.
                Murmur.UserInfo.UserName: name,
                Murmur.UserInfo.UserComment: comment,
            }
    
    def setInfo(self, id, info, current=None):
        return -1  # for now, let's pass through
        
        # We only allow comment updates.  Everything else is immutable.
        if Murmur.UserInfo.UserComment not in info or len(info) > 1:
            return 0
        
        updated = Ticket.objects(character__id=id).update(set__comment=info[Murmur.UserInfo.UserComment])
        if not updated: return 0
        return 1
    
    def nameToId(self, name, current=None):
        return Ticket.objects(character__name=name, registered__exists=True, registered__not=None).scalar('character__id').first() or -2
    
    def idToName(self, id, current=None):
        return Ticket.objects(character__id=id, registered__exists=True, registered__not=None).scalar('character__name').first() or ''
    
    def idToTexture(self, id, current=None):
        log.debug("idToTexture %d", id)
        return ''  # TODO: Pull the character's image from CCP's image server.  requests.get, CACHE IT
    
    def setTexture(self, id, texture, current=None):
        return -1  # we currently don't handle these
    
    def registerUser(self, info, current=None):
        log.debug('registerUser "%s"', name)
        return 0
    
    def unregisterUser(self, id, current=None):
        log.debug("unregisterUser %d", id)
        return 0
    
    # TODO: Do we need this?  Seems only defined on Server, not our class.
    # def getRegistration(self, id, current=None):
    #     return (-2, None, None)
    
    def getRegisteredUsers(self, filter, current=None):
        results = Ticket.objects(registered__exists=True, registered__not=None).scalar('character__id', 'character__name')
        if filter.strip(): results.filter(character__name__icontains=filter)
        return dict(results)










def checkSecret(fn):
    def inner(self, *args, **kw):
        if not self.__secret:
            return fn(self, *args, **kw)
        
        current = kw.get('current', args[-1])
        
        if not current or current.ctx.get('secret', None) != self.__secret:
            log.error("Server transmitted invalid secret.")
            raise Murmur.InvalidSecretException()
        
        return fn(self, *args, **kw)
    
    return inner


def errorRecovery(value=None, exceptions=(Ice.Exception, )):
    def decorator(fn):
        def inner(*args, **kw):
            try:
                return func(self, *args, **kw)
            except exceptions, e:
                raise
            except:
                log.exception("Unhandled error.")
                return value
        
        return inner
    
    return decorator
                


class MumbleMetaCallback(Murmur.MetaCallback):
    def __init__(self, app):
        Murmur.MetaCallback.__init__(self)
        self.app = app
    
    @errorRecovery()
    @checkSecret
    def started(self, server, current=None):
        """Attach an authenticator to any newly started virtual servers."""
        log.info("Attaching authenticator to virtual server %d.", server.id())
        
        try:
            server.setAuthenticator(self.app.auth)
        except (Murmur.InvalidSecretException, Ice.UnknownUserException) as e:
            if getattr(e, 'unknown', None) != 'Murmur::InvalidSecretException':
                raise
            
            log.error("Invalid Ice secret.")
            return
    
    @errorRecovery()
    @checkSecret
    def stopped(self, server, current=None):
        if not self.app.connected:
            return
        
        try:
            log.info("Virtual server %d has stopped.", server.id())
        except Ice.ConnectionRefusedException:
            self.app.connected = False


class MumbleAuthenticatorApp(Ice.Application):
    def __init__(self, host='127.0.0.1', port=6502, secret=None, *args, **kw):
        super(MumbleAuthenticatorApp, self).__init__(*args, **kw)
        
        self.__host = host
        self.__port = port
        self.__secret = secret
        
        self.connected = False
        self.meta = None
        self.metacb = None
        self.auth = None
    
    def run(self):
        self.shutdownOnInterrupt()
        
        if not self.initializeIceConnection():
            return 1
        
        self.communicator().waitForShutdown()
        self.watchdog.cancel()
        
        if self.interrupted():
            log.warning("Caught interrupt; shutting down.")
        
        return 0
    
    def initializeIceConnection(self):
        ice = self.communicator()
        
        if self.__secret:
            ice.getImplicitContext().put("secret", self.__secret)
        else:
            log.warning("No secret defined; consider adding one.")
        
        log.info("Connecting to Ice server: %s:%d", self.__host, self.__port)
        
        base = ice.stringToProxy('Meta:tcp -h {0} -p {1}'.format(self.__host, self.__port))
        self.meta = Murmur.MetaPrx.uncheckedCast(base)
        
        adapter = ice.createObjectAdapterWithEndpoints('Callback.Client', 'tcp -h {0}'.format(self.__host))
        adapter.activate()
        
        metacbprx = adapter.addWithUUID(MumbleMetaCallback(self))
        self.metacb = Murmur.MetaCallbackPrx.uncheckedCast(metacbprx)
        
        authprx = adapter.addWithUUID(MumbleAuthenticator())
        self.auth = Murmur.ServerUpdatingAuthenticatorPrx.uncheckedCast(authprx)
        
        return self.attachCallbacks()
    
    def attachCallbacks(self, quiet=False):
        try:
            log.info("Attaching to live servers.")
            
            self.meta.addCallback(self.metacb)
            
            for server in self.meta.getBootedServers():
                log.debug("Attaching to virtual server %d.", server.id())
                server.setAuthenticator(self.auth)
        
        except Ice.ConnectionRefusedException:
            log.error("Server refused connection.")
            self.connected = False
            return False
        
        except (Murmur.InvalidSecretException, Ice.UnknownUserException) as e:
            self.connected = False
            
            if isinstance(e, Ice.UnknownUserException) and e.unknown != 'Murmur:InvalidSecretException':
                raise  # we can't handle this error
            
            log.exception("Invalid Ice secret.")
            return False
        
        self.connected = True
        return True
    
    def checkConnection(self):
        try:
            self.failedWatch = not self.attachCallbacks()
        
        except Ice.Exception as e:
            log.exception("Failed connection check.")
        
        
        
        
        
        






def main(secret):
    """
    
    PYTHONPATH=/usr/local/lib/python2.7/site-packages paster shell
    from brave.mumble.service import main
    
    """
    log.info("Ice initializing.")
    
    prop = Ice.createProperties([])
    prop.setProperty("Ice.ImplicitContext", "Shared")
    prop.setProperty("Ice.MessageSizeMax", "65535")
    prop.setProperty("Ice.Default.EncodingVersion", "1.0")
    
    idd = Ice.InitializationData()
    idd.properties = prop
    
    ice = Ice.initialize(idd)
    
    log.info("here")
    
    if secret:
        ice.getImplicitContext().put("secret", secret)
    
    prx = ice.stringToProxy(connection)
    
    try:
        prx.ice_ping()
    except Ice.Exception:
        log.error("Unable to ping Murmur Ice interface.")
        return
    
    log.info("there")
    
    # Magic.  Try loading the Ice slice from the Mumble server itself.
    
    try:
        op = IcePy.Operation('getSlice', Ice.OperationMode.Idempotent, Ice.OperationMode.Idempotent, True, (), (), (), IcePy._t_string, ())
        slice = op.invoke(prx, ((), None))
    except (TypeError, Ice.OperationNotExistException):
        log.exception("Unable to dynamically load slice information; Ice version too new?")
    else:
        # Swap out the (potentially old) existing slice information.
        with tempfile.NamedTemporaryFile(suffix='.ice') as tmp:
            try:
                tmp.write(slice)
                tmp.flush()
                Ice.loadSlice(tmp.name)
                log.info("Loaded dynamic Murmur.ice slice information.")
            except RuntimeError:
                log.exception("Unable to process dynamic slice information.")
                return
        
        global Murmur
        import Murmur as m
        Murmur = m
    
    meta = Murmur.MetaPrx.checkedCast(prx)
    
    log.info("everywhere")
    
    adapter = ice.createObjectAdapterWithEndpoints(b"Callback.Client", b"tcp -h 127.0.0.1")
    adapter.activate()
    
    log.info("Connected to: Mumble %s", meta.getVersion()[:3])
    
    for server in meta.getBootedServers():
        authenticator = Murmur.ServerUpdatingAuthenticatorPrx.uncheckedCast(adapter.addWithUUID(ServerAuthenticator(server, meta)))
        server.setAuthenticator(authenticator)
    
    log.info("Ice registration complete.")
    
    try:
        ice.waitForShutdown()
    except KeyboardInterrupt:
        log.info("Ice shutting down due to caught ^C.")
    
    # TODO: Do we have to unregister anything here?
    # meta.removeCallback(metaR)
    ice.shutdown()
    
    log.info("Ice stopped.")




"""


id = server.registerUser(username=username, password=password)

server.kickPlayer(id, reason)
server.unregisterUser(id)

user = server.getRegistration(id)
user.password = password
server.updateRegistration(id, user)

for is, name in server.getRegisteredUsers(""):
    pass




def clean_idlers(server):
    users = server.getUsers()
    
    for user in users:
        if user.idlesecs > 5000 and user.channel != 4:
            state = server.getState(user.session)
            if state:
                state.channel = 4
                server.setState(state)



if __name__ == "__main__":
    global contextR

    print "Creating callbacks...",
    ice = Ice.initialize(sys.argv)

    meta = Murmur.MetaPrx.checkedCast(ice.stringToProxy('Meta:tcp -h 127.0.0.1 -p 6502'))

    adapter = ice.createObjectAdapterWithEndpoints("Callback.Client", "tcp -h 127.0.0.1")
    adapter.activate()

    for server in meta.getBootedServers():
      serverR=Murmur.ServerUpdatingAuthenticatorPrx.uncheckedCast(adapter.addWithUUID(ServerAuthenticatorI(server, adapter)))
      server.setAuthenticator(serverR)

    print "Done"
    
    map = {};
    map[Murmur.UserInfo.UserName] = 'TestUser';

    for server in meta.getBootedServers():
      ids= server.getUserIds(["TestUser"])
      for name,id in ids.iteritems():
        if (id > 0):
          print "Will unregister ", id
          server.unregisterUser(id)
      server.registerUser(map)

    print 'Script running (press CTRL-C to abort)';
    try:
        ice.waitForShutdown()
    except KeyboardInterrupt:
        print 'CTRL-C caught, aborting'

    meta.removeCallback(metaR)
    ice.shutdown()
    print "Goodbye"

"""
