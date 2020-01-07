import requests

from logging import getLogger
from appdirs import AppDirs
from os.path import exists, join as path_join
from configparser import ConfigParser

log = getLogger("Fbx-Monitor")


class NotAuthorized (Exception):
    pass


class ApiRequest:
    api_url = "http://mafreebox.freebox.fr/api/v4/"
    challenge = None
    app_id = "com.wcentric.zabbix"
    app_name = "FH Monitoring"
    app_version = "0.0.1"
    app_token = None
    session_token = None

    def is_logged(self):
        result = self.get("login")
        return result["logged_in"]

    def request_authorize(self):
        from socket import gethostname

        payload = {
            "app_id": self.app_id,
            "app_name": self.app_name,
            "app_version": self.app_version,
            "device_name": gethostname()
        }
        app_register = self.post("login/authorize", payload)
        self.app_token = app_register["app_token"]
        return app_register["track_id"]

    def get_track(self, track_id):
        result = self.get("login/authorize/" + str(track_id))
        return result["status"]

    def authenticate(self):
        from time import sleep

        if self.is_logged():
            return True

        if self.app_token is None:
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
        log.debug(answer.status_code)
        log.debug(answer.json())

        if answer.status_code == 403:
            log.warning("Not authenticated.")
            raise NotAuthorized

        if answer.status_code != 200:
            log.critical("Status code not handled.")
            raise
        body = answer.json()
        if not body["success"]:
            log.error("Message body not success.")
            raise

        if "challenge" in body["result"]:
            self.challenge = body["result"]["challenge"]

        return body["result"]

    def get(self, url):
        if self.session_token is not None:
            log.debug("Using session %s" % self.session_token)
            headers = {"X-Fbx-App-Auth": self.session_token}
        else:
            headers = None

        try:
            return self.parse(requests.get(self.api_url + url, headers=headers))
        except NotAuthorized:
            self.authenticate()
            if self.session_token is not None:
                headers = {"X-Fbx-App-Auth": self.session_token}
            return self.parse(requests.get(self.api_url + url, headers=headers))

    def post(self, url, data):
        if self.session_token is not None:
            log.debug("Using session %s" % self.session_token)
            headers = {"X-Fbx-App-Auth": self.session_token}
        else:
            headers = None

        try:
            return self.parse(requests.post(self.api_url + url, json=data, headers=headers))
        except NotAuthorized:
            self.authenticate()
            if self.session_token is not None:
                headers = {"X-Fbx-App-Auth": self.session_token}
            return self.parse(requests.post(self.api_url + url, json=data, headers=headers))

    def start_session(self):
        from hmac import digest as hmac_digest
        from hashlib import sha1

        log.debug("Start session")
        log.debug(self.challenge)
        log.debug(self.app_token)
        password = hmac_digest(bytes(self.app_token, "utf-8"), bytes(self.challenge, "utf-8"), sha1)
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
    api = ApiRequest()
    app_dir = AppDirs(appname="fbx-Zabbox", appauthor="Webcentric")

    def __init__(self):
        self.load()

    def load(self):
        file_path = path_join(self.app_dir.user_cache_dir, "config.ini")
        log.info("Load from %s" % file_path)
        config = ConfigParser()
        config.read([file_path])

        if 'fh-fbx-monitoring' in config:
            for key in config['fh-fbx-monitoring']:
                if hasattr(self.api, key):
                    setattr(self.api, key, config['fh-fbx-monitoring'][key])

    def save(self):
        print("save")
        if not exists(self.app_dir.user_cache_dir):
            from os import makedirs
            makedirs(self.app_dir.user_cache_dir)

        file_path = path_join(self.app_dir.user_cache_dir, "config.ini")
        log.info("Cache to %s" % file_path)
        config = ConfigParser()
        config['fh-fbx-monitoring'] = self.api.__dict__
        with open(file_path, 'w') as fp:
            config.write(fp)

    def system(self):
        return self.api.get("system")


if __name__ == "__main__":
    monitoring = MonitoringAgent()
    print(monitoring.system())
    monitoring.save()
