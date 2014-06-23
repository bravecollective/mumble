# encoding: utf-8

# from __future__ import unicode_literals

import sys
import time
import datetime
import tempfile
import Ice
import IcePy
from threading import Timer
from web.core import config
from marrow.util.convert import number, array
from marrow.util.bunch import Bunch
from collections import defaultdict

from brave.mumble.auth.model import Ticket
from brave.api.client import API

Ice.loadSlice(b'', [b'-I' + (Ice.getSliceDir() or b'/usr/local/share/Ice-3.5/slice/'), b'Murmur.ice'])
import Murmur


log = __import__('logging').getLogger(__name__)
icelog = __import__('logging').getLogger('ice')



AUTH_FAIL = (-1, None, None)
NO_INFO = (False, {})



class IdlerGroup(object):
    __slots__ = ('time', 'target', 'channels')
    
    def __init__(self, time, target, channels=None):
        self.time = number(time)
        self.target = number(target)
        self.channels = array(channels) if channels else []


class IdlerHandler(object):
    def __init__(self):
        from web.core import config
        self.channel = number(config.get('idle.channel', 64))
        self.idlers = array(config.get('idle.groups', 'basic'))
        self.config = Bunch({i: IdlerGroup(
                time = config.get('idle.' + i + '.time', 3600),  # default: 1 hour
                target = config.get('idle.' + i + '.channel', self.channel),  # default: 64
                channels = config.get('idle.' + i + '.channels', ''),  # default: all
            ) for i in self.idlers})
        
        self.map = defaultdict()
        self.exclude = list(set((i.target for i in self.config.itervalues())))
        
        for config in self.config.itervalues():
            if config.channels:
                self.map.update({chan: config for chan in config.channels})
            else:
                self.map.default_factory = lambda: config
    
    def __call__(self, server):
        users = server.getUsers()
        exclude = self.exclude
        map = self.map
        
        for user in users:
            if user.channel in exclude: continue
            
            try:
                config = map[user.channel]
            except KeyError:
                continue
            
            if user.idlesecs > config.time:
                state = server.getState(user.session)
                if state:
                    state.channel = config.channel
                    server.setState(state)


class MumbleAuthenticator(Murmur.ServerUpdatingAuthenticator):
    """MongoDB-backed Mumble authentication agent.
    
    Murmur ICE reference: http://mumble.sourceforge.net/slice/Murmur.html
    """
    
    # TODO: Factor out all the "registered__exists=True, registered__not=None" clones.
    
    # ServerAuthenticator
    
    def authenticate(self, name, pw, certificates, certhash, certstrong, current=None):
        """Authenticate a Mumble user.
        
        * certificates: the X509 certificate chain of the user's certificate
        
        Returns a 3-tuple of user_id, user_name, groups.
        """
        
        log.info('authenticate "%s" %s', name, certhash)
        
        # Look up the user.
        try:
            user = Ticket.objects.only('tags', 'seen', 'password', 'corporation__id', 'alliance__id', 'alliance__ticker', 'character__id', 'token').get(character__name=name)
        except Ticket.DoesNotExist:
            log.warn('User "%s" not found in the Ticket database.', name)
            return AUTH_FAIL
        
        if not isinstance(pw, basestring):
            log.warn('pass-notString-fail "%s"', name)
            return AUTH_FAIL
        elif pw == '':
            log.warn('pass-empty-fail "%s"', name)
            return AUTH_FAIL
        elif user.password == '':
            log.warn('pass-not-set-fail "%s"', name)
            return AUTH_FAIL
        elif not Ticket.password.check(user.password, pw):
            log.warn('pass-fail "%s"', name)
            return AUTH_FAIL
        
        if user.seen > (datetime.now() - timedelta(days = 2))
            # -------
            # Check to make sure that the user is still valid and that their token has not expired yet.
            # -------
            
            # load up the API
            api = API(config['api.endpoint'], config['api.identity'], config['api.private'], config['api.public'])
            
            # is mumble set to just use the main ticket DB if
            config_bypass_core = config['mumble.bypassCore'] == 'True' or config['mumble.bypassCore'] == 'true'
            
            try:
                # If the token is not valid, deny access
                if not config_bypass_core and not Ticket.authenticate(user.token):
                    return AUTH_FAIL
            except Exception as e:
                log.warning("Exception occured when attempting to authenticate user {0}.".format(name))
                return AUTH_FAIL
                
            # Update the local user object against the newly refreshed DB ticket.
            user = Ticket.objects.only('tags', 'seen', 'password', 'corporation__id', 'alliance__id', 'alliance__ticker', 'character__id', 'token').get(character__name=name)
            
            # Define the registration date if one has not been set.
            Ticket.objects(character__name=name, registered=None).update(set__registered=datetime.datetime.utcnow())
        
        for tag in ('member', 'blue', 'guest', 'mumble'):
            if tag in user.tags: break
        else:
            log.warn('User "%s" does not have permission to connect to this server.', name)
            return AUTH_FAIL
        
        tags = [i.replace('mumble.', '') for i in user.tags]
        
        tags.append('corporation-{0}'.format(user.corporation.id))
        if user.alliance and user.alliance.id:
            tags.append('alliance-{0}'.format(user.alliance.id))
        
        log.debug('success "%s" %s', name, ' '.join(tags))
        
        ticker = user.alliance.ticker if user.alliance.ticker else '----'
        return (user.character.id, '[{0}] {1}'.format(ticker, name), tags)
    
    def getInfo(self, id, current=None):
        return False, {}  # for now, let's pass through
        
        log.debug('getInfo %d', id)
        
        try:
            seen, name, ticker, comment = Ticket.objects(character__id=id).scalar('seen', 'character__name', 'alliance__ticker', 'comment').first()
        except TypeError:
            return NO_INFO
        
        if name is None: return NO_INFO
        if not ticker: ticker = '----'
        
        return True, {
                # Murmur.UserInfo.UserLastActive: seen,  # TODO: Verify the format this needs to be in.
                Murmur.UserInfo.UserName: '[{0}] {1}'.format(ticker, name),
                Murmur.UserInfo.UserComment: comment,
            }
    
    def nameToId(self, name, current=None):
        ticker, _, name = name.partition('] ')
        return Ticket.objects(character__name=name).scalar('character__id').first() or -2
    
    def idToName(self, id, current=None):
        user = Ticket.objects(character__id=id).only('character__name', 'alliance__ticker').first()
        if not user: return ''
        
        ticker = user.alliance.ticker or '----'
        
        return '[{0}] {1}'.format(user.character.name, user.alliance.ticker)
    
    def idToTexture(self, id, current=None):
        log.debug("idToTexture %d", id)
        return ''  # TODO: Pull the character's image from CCP's image server.  requests.get, CACHE IT
    
    # ServerUpdatingAuthenticator
    
    """
    
    def setInfo(self, id, info, current=None):
        return -1  # for now, let's pass through
        
        # We only allow comment updates.  Everything else is immutable.
        if Murmur.UserInfo.UserComment not in info or len(info) > 1:
            return 0
        
        updated = Ticket.objects(character__id=id).update(set__comment=info[Murmur.UserInfo.UserComment])
        if not updated: return 0
        return 1
    
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
        results = Ticket.objects.scalar('character__id', 'character__name')
        if filter.strip(): results.filter(character__name__icontains=filter)
        return dict(results)
    
    """










def checkSecret(fn):
    def inner(self, *args, **kw):
        if not self.app.__secret:
            return fn(self, *args, **kw)
        
        current = kw.get('current', args[-1])
        
        if not current or current.ctx.get('secret', None) != self.app.__secret:
            log.error("Server transmitted invalid secret.")
            raise Murmur.InvalidSecretException()
        
        return fn(self, *args, **kw)
    
    return inner


def errorRecovery(value=None, exceptions=(Ice.Exception, )):
    def decorator(fn):
        def inner(*args, **kw):
            try:
                return fn(*args, **kw)
            except exceptions:
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
        log.debug("Attaching authenticator to virtual server %d running Mumble %s.", server.id(), '.'.join(str(i) for i in self.app.meta.getVersion()[:3]))

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
        
        self.watchdog = None
        self.connected = False
        self.meta = None
        self.metacb = None
        self.auth = None
        
        self.clean_idlers = IdlerHandler()
    
    def run(self, args):
        self.shutdownOnInterrupt()
        
        if not self.initializeIceConnection():
            return 1
        
        # Trigger the watchdog.
        self.failedWatch = True
        self.checkConnection()
        
        self.communicator().waitForShutdown()
        if self.watchdog: self.watchdog.cancel()
        
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
                log.debug("Attaching authenticator to virtual server %d running Mumble %s.", server.id(), '.'.join(str(i) for i in self.meta.getVersion()[:3]))
                server.setAuthenticator(self.auth)
                
                self.clean_idlers(server)
        
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
        
        self.watchdog = Timer(30, self.checkConnection)  # TODO: Make this configurable.
        self.watchdog.start()



class CustomLogger(Ice.Logger):
    def _print(self, message):
        icelog.info(message)
    
    def trace(self, category, message):
        icelog.debug("trace %s\n%s", category, message)
    
    def warning(self, message):
        icelog.warning(message)
    
    def error(self, message):
        icelog.error(message)



def main(secret):
    """
    
    PYTHONPATH=/usr/local/lib/python2.7/site-packages paster shell
    from brave.mumble.service import main; main('')
    
    """
    log.info("Ice initializing.")
    
    prop = Ice.createProperties([])
    prop.setProperty("Ice.ImplicitContext", "Shared")
    prop.setProperty("Ice.MessageSizeMax", "65535")
    prop.setProperty("Ice.Default.EncodingVersion", "1.0")
    
    idd = Ice.InitializationData()
    idd.logger = CustomLogger()
    idd.properties = prop
    
    app = MumbleAuthenticatorApp(secret=secret)
    app.main(['brave-mumble'], initData=idd)
    
    log.info("Shutdown complete.")
