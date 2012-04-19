#! /usr/bin/python
# -*- coding:utf-8 -*-

import json, httplib, sys
from urllib import urlencode, quote_plus, quote
from ConfigParser import ConfigParser
from datetime import datetime
from base64 import b64encode
from time import time
import hmac
from hashlib import sha1
import logging
from logging.handlers import TimedRotatingFileHandler

CONFIG = '/etc/logotwit.ini'

class Logotwit(object):
    _APIhost    = 'api.twitter.com'
    _conn       = None
    _conf       = None
    _nonce      = ''
    _length     = 140
    _log        = None

    def __init__(self):
        self._conn = httplib.HTTPSConnection(self._APIhost)
        self._conf = ConfigParser()
        self._conf.read(CONFIG)

        std_handler = logging.handlers.TimedRotatingFileHandler(self._conf.get('log', 'path'), when='midnight')
        std_handler.setFormatter(logging.Formatter('%(asctime)-15s %(levelname)-8s %(message)s'))
        self._log = logging.getLogger('logotwit')
        self._log.setLevel(logging.DEBUG)
        self._log.addHandler(std_handler)

    def _signature(self, params, method, url, status=None):
        """
        Подписывание запросов
        """
        if status:
            params['status'] = quote(status)
        params['oauth_consumer_key'] = self._conf.get('oauth', 'consumer_key')
        params['oauth_nonce'] = quote_plus(self._getOAuthNonce())
        params['oauth_signature_method'] = self._conf.get('oauth', 'signature_method')
        params['oauth_timestamp'] = int(time())
        params['oauth_token'] = self._conf.get('oauth', 'access_token')
        params['oauth_version'] = self._conf.get('oauth', 'version')
        msg = quote_plus(reduce(lambda res, key: '%s&%s=%s' % (res, key, params[key]), sorted(params), '')[1:])
        msg = '&'.join([method.upper(), quote_plus(url), msg])
        signing_key = '&'.join([self._conf.get('oauth', 'consumer_secret'), self._conf.get('oauth', 'access_token_secret')])
        params['oauth_signature'] = quote_plus(b64encode(hmac.new(signing_key, msg, sha1).digest()))
        return params

    def _OAuthHeaders(self, params, method, url, status=None):
        params = self._signature(params, method, url, status)
        header = 'OAuth oauth_consumer_key="%s",' +\
            'oauth_nonce="%s",' +\
            'oauth_signature="%s",' +\
            'oauth_signature_method="%s",' +\
            'oauth_timestamp="%s",' +\
            'oauth_token="%s",' +\
            'oauth_version="%s"'
        header = header % (params['oauth_consumer_key'], params['oauth_nonce'], params['oauth_signature'],
        params['oauth_signature_method'], params['oauth_timestamp'], params['oauth_token'], params['oauth_version'])
        return {'Authorization': header}

    def _getOAuthNonce(self):
        """
        Получение параметра авторизации ouath_nonce
        служащего для идентификации уникальности каждого твита
        Помогает не дублировать ошибочно отправленные
        подряд твиты
        """
        if not self._nonce:
            self._nonce = hmac.new(self._conf.get('oauth', 'nonce_salt'), datetime.now().isoformat()).digest()
            self._nonce = unicode(b64encode(self._nonce))[:32].encode('utf-8')
        return self._nonce

    def home_timeline(self, count=5):
        parameters = {
            'count': count # Количество получаемых твитов
        }
        path = '/1/statuses/home_timeline.json'
        HTTPmethod = 'GET'
        sign = self._OAuthHeaders(parameters.copy(), HTTPmethod, 'https://%s%s' % (self._APIhost, path))
        self._conn.request(HTTPmethod, path + '?' + urlencode(parameters), None, sign)
        response = self._conn.getresponse()
        if response.status == httplib.OK:
            print json.loads(response.read())
        else:
            print response.getheaders()
            print response.read()

    def update(self, status):
        self._log.info('твит: %s', status)
        parameters = {
                'status': status.strip()[:self._length]
        }
        path = '/1/statuses/update.json'
        HTTPmethod = 'POST'
        sign = self._OAuthHeaders({}, HTTPmethod, 'https://%s%s' % (self._APIhost, path), parameters['status'])
        self._conn.request(HTTPmethod, path, urlencode(parameters), sign)
        response = self._conn.getresponse()
        if response.status == httplib.OK:
            self._log.info('ОК')
        else:
            self._log.error('%s\n%s', response.getheaders(), response.read())

if __name__ == '__main__':
    logotwit = Logotwit()
    logotwit.update(' '.join(sys.stdin.readlines()))
