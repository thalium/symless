import json
import os


class Settings:
    def __init__(self):

        self.settings = {}
        with open(
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "config/settings.json"), "rb"
        ) as settings_file:
            self.settings = json.load(settings_file)
        self.DEBUG = False
        if "debug" in self.settings:
            self.DEBUG = self.settings["debug"] == 1

    def is_debug(self):
        return self.DEBUG


def load_settings():
    return Settings()
