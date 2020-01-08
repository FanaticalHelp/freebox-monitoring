#!/usr/bin/env python3

"""Get Foreebox metrics for monitoring"""

import requests

import logging
from appdirs import AppDirs
from os.path import exists, join as path_join
from configparser import ConfigParser

import sys
log = logging.getLogger("Fbx-Monitor")


class ApiError (Exception):
    """
    Class for not authorized access
    """
    body = None

    def __init__(self, body):
        super(__class__, self).__init__()
        self.body = body


class NotAuthorized(ApiError):
    pass


class AuthRequired(ApiError):
    pass


class InvalidToken(ApiError):
    pass


class ApiRequest:
    """
    Low level Api calls and authentication
    """

    api_url = "http://mafreebox.freebox.fr/api/v4/"
    challenge = None
    app_id = "com.wcentric.zabbix"
    app_name = "FH Monitoring"
    app_version = "0.0.1"
    app_token = None
    session_token = None

    def is_logged(self):
        """
        Check if this application is logged on the Freebox
        """

        result = self.get("login")
        return result["logged_in"]

    def request_authorize(self):
        """
        Register the application on the Freebox
        """

        from socket import gethostname

        payload = {
            "app_id": self.app_id,
            "app_name": self.app_name,
            "app_version": self.app_version,
            "device_name": gethostname()
        }
        print("You need to press YES on the box.")
        app_register = self.post("login/authorize", payload)
        self.app_token = app_register["app_token"]
        return app_register["track_id"]

    def get_track(self, track_id):
        """
        Check application authorization status
        """

        result = self.get("login/authorize/" + str(track_id))
        return result["status"]

    def authenticate(self):
        """
        Ask the user to allow the application (require operation on the box)
        """

        from time import sleep

        if self.is_logged():
            return True

        if self.app_token is not None:
            try:
                self.start_session()
                return True
            except NotAuthorized:
                log.warning("Not authorized.")
                self.session_token = None

        track_id = self.request_authorize()
        status = "pending"
        while status == "pending":
            sleep(5)
            status = self.get_track(track_id)

        if status != "granted":
            log.error("Application not granted")
            raise

        self.start_session()

    def parse(self, answer):
        """
        Parse API answer and raise an exception if the answer is an error
        """

        body = answer.json()
        log.debug(answer.status_code)
        log.debug(body)

        if "result" in body and "challenge" in body["result"]:
            self.challenge = body["result"]["challenge"]

        if answer.status_code == 403:
            if body['error_code'] == "invalid_token":
                self.session_token = None
                log.warning("Invalid token, delete existing token.")
                raise InvalidToken(body)

            elif body['error_code'] == 'auth_required':
                log.debug('Require authentication.')
                raise AuthRequired(body)

            log.warning("Not authenticated.")
            raise ApiError(body)

        if answer.status_code != 200:
            log.critical("Status code not handled.")
            raise

        if not body["success"]:
            log.error("Message body not success.")
            raise

        if "result" in body:
            return body["result"]
        else:
            return True

    def _send_request(self, method, url, json = None):
        log.debug("Using session %s, Call %s (%s)" % (self.session_token, url, method.__name__))
        if self.session_token is not None:
            headers = {"X-Fbx-App-Auth": self.session_token}
        else:
            headers = None

        if json is not None:
            return self.parse(method(self.api_url + url, json=json, headers=headers))
        else:
            return self.parse(method(self.api_url + url, headers=headers))

    def _call_api(self, method, url, json = None):
        try:
            return self._send_request(method, url, json)
        except AuthRequired:
            self.start_session()
            return self._send_request(method, url, json)

    def get(self, url):
        """
        Make a get request on API
        """

        return self._call_api(requests.get, url)

    def post(self, url, data):
        """
        Make a post request on API Server
        """

        return self._call_api(requests.post, url, json=data)

    def start_session(self):
        """
        Start a new session
        """

        import hmac as HMAC_Factory
        from hashlib import sha1

        if self.app_token is None:
            raise InvalidToken(None)

        if self.challenge is None:
            self.is_logged()

        log.debug("Start session")
        log.debug(self.challenge)
        log.debug(self.app_token)

        hmac = HMAC_Factory.new(bytes(self.app_token, "utf-8"), bytes(self.challenge, "utf-8"), 'sha1')

        password = hmac.digest()
        password_hex = ''.join('{:02x}'.format(x) for x in password)
        log.debug(password_hex)
        payload = {
            "app_id": self.app_id,
            "password": password_hex
        }
        log.debug(payload)
        result = self.post("login/session", payload)
        self.session_token = result["session_token"]
        log.debug("Session Opened")
        log.debug(result)
        log.debug(self.session_token)


class MonitoringAgent:
    """
    The high level API Client
    """

    api = ApiRequest()

    def authorize(self):
        self.api.app_token = None
        self.api.session_token = None
        self.api.authenticate()

    def system(self):
        """
        Get System metrics and configuration
        :return: dict of values
        """

        return self.api.get("system")

    def connection(self):
        """
        Get Connection status
        :return:
        """
        return self.api.get("connection")

    def switch(self):
        """
        Get Switch status
        :return:
        """
        return self.api.get("switch/status")

    def freeplugs(self):
        """
        Get Freeplugs
        :return:
        """
        return self.api.get("freeplug")

    def wifi_ap(self):
        """
        Get AP connected to Wifi
        :return:
        """
        return self.api.get("wifi/ap")


class Settings:
    config = ConfigParser()
    app_dir = AppDirs(appname="fbx-Zabbox", appauthor="Webcentric")
    file_path_cache = path_join(app_dir.user_cache_dir, "config.ini")
    instances = []

    def __init__(self):
        log.debug("Load file %s", self.file_path_cache)
        self.config.read([self.file_path_cache])

    def save(self):
        if not exists(self.app_dir.user_cache_dir):
            from os import makedirs
            makedirs(self.app_dir.user_cache_dir)

        for i in self.instances:
            self.save_object(i)

        with open(self.file_path_cache, 'w') as fp:
            self.config.write(fp)

    def handle(self, instance):
        self.load_object(instance)
        self.instances.append(instance)

    def load_object(self, instance):
        section = instance.__class__.__name__
        log.debug("Load instance of %s" % section)

        if self.config.has_section(section):

            for key in self.config.options(section):
                if hasattr(instance, key):
                    setattr(instance, key, self.config.get(section, key))

    def save_object(self, instance):
        section = instance.__class__.__name__
        if not self.config.has_section(section):
            self.config.add_section(section)

        for key in instance.__dict__:
            val = getattr(instance, key)
            if val is not None:
                self.config.set(section, key, val)


if __name__ == "__main__":
    from argparse import ArgumentParser

    config = Settings()
    monitoring = MonitoringAgent()
    config.handle(monitoring)
    config.handle(monitoring.api)

    callables = [func for func in dir(MonitoringAgent) if callable(getattr(MonitoringAgent, func)) and not func.startswith('__')]

    command = ArgumentParser(description="Call Freebox API.")
    command.add_argument('action', action='store', choices=callables, help='Action or API method to execute')
    command.add_argument('-d', '--debug', action='store_true', help="Set debug mode")
    args = command.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)
        log.addHandler(logging.StreamHandler(sys.stderr))

    if args.action == "authorize":
        monitoring.authorize()

    else:
        try:
            import json
            print(json.dumps(getattr(monitoring, args.action)()))
        except InvalidToken:
            print("ERROR: Invalid token, need to authorize application.")
            config.save()
            exit(1)

    config.save()
