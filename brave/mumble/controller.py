# encoding: utf-8

from __future__ import unicode_literals

from web.auth import authenticated, user
from web.core import Controller

from brave.mumble.util import StartupMixIn
from brave.mumble.auth.controller import AuthenticationMixIn


log = __import__('logging').getLogger(__name__)


class RootController(Controller, StartupMixIn, AuthenticationMixIn):
    def index(self):
        if authenticated:
            return 'brave.mumble.template.index', dict()

        return 'brave.mumble.template.welcome', dict()
    
    def passwd(self, password):
        u = user._current_obj()
        
        try:
            u.password = password
            u.save()
        except:
            log.exception("Error attempting to assign password.")
            return 'json:', dict(success=False, message="Something terrible happened.")
        
        return 'json:', dict(success=True)
