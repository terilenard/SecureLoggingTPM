import time
import threading


from logger import Logger
from mqtt_client import MQTTClient
from utils import json_to_dict
from log import logger as app_logger


class LogManager:

    def __init__(self, config):
        '''
        config: dict of config params
        '''
        self._logger = Logger(
                        config["profile_name"], 
                        config["profile_dir"],
                        config["user_dir"], 
                        config["system_dir"], 
                        config["log_dir"],
                        config["nv_time_path"],
                        config["nv_sign_path"],
                        config["nv_epoch_path"],
                        config["ai_key"],
                        config["aik_attributes"])

        self._mqtt_client = MQTTClient(
                                config["mqtt-user"],
                                config["mqtt-passwd"],
                                config["mqtt-host"],
                                config["mqtt-port"],
                                service_name="TPMLogger",
                                on_message_callback=self._on_new_log)

        self._should_run = False
        
        # Timer to periodically check to safe logs to file
        self._log_timer = threading.Timer(5, self._on_log_to_file) 

    def _on_new_log(self, mqttc, obj, msg):

        if msg is not None:
            commit = self._logger.log(msg.payload)
            print(commit)

    def _on_log_to_file(self):

        if len(self._logger.get_logs() < Logger.LOG_COUNT_LIMIT):
            return
        else:
            # TODO: write to file
            pass

    def start(self):
        if self._logger:
            # This call works after provision
            # For provisioning run:
            # self._logger.setup(do_provision=True, create_nv=True, create_aik=True)
            self._logger.setup()
            app_logger.info("Logger setup complete.")
        else:
            app_logger.error("Logger error setup.")

        self._mqtt_client.connect()
        self._log_timer.start()

    def run(self):
        self._should_run = True 
        try:
            app_logger.info("Logger loop started.")
            while(self._should_run):
                time.sleep(0.1)
        except:
            self._should_run = False
            self.stop()

    def stop(self):
        app_logger.info("Stopping Logger loop.")
        if self._logger:
            self._logger.close()
            app_logger.info("Closed TPM Logger.")

        if self._mqtt_client:
            self._mqtt_client.stop()
            app_logger.info("Closed MQTT cliend.")

        if self._log_timer:
            self._log_timer.cancel()


if __name__ == "__main__":

    config = json_to_dict("config.json")
    log_manager = LogManager(config)

    try:
        log_manager.start()
        log_manager.run()

    except Exception:
        log_manager.stop()
