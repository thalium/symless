import json
import os


class Settings:
    def __init__(self):

        self.settings = {}
        with open(
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "config/settings.json"), "rb"
        ) as settings_file:
            self.settings = json.load(settings_file)
        self.LOG_LEVEL = 30
        if "log_level" in self.settings:
            self.LOG_LEVEL = self.settings["log_level"]

    def get_log_level(self):
        return self.LOG_LEVEL


def load_settings():
    return Settings()


settings = load_settings()
