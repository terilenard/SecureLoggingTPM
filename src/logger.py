import pprint
import json

from tpm2_pytss import *

from utils import sha256, json_to_dict
from log_model import LogModel
from epoch_model import EpochModel

class Logger(object):

    PCR = 23

    def __init__(self, profile_name, profile_dir,
                 user_dir, system_dir, log_dir,
                 nv_time_path, nv_sign_path, nv_epoch_path,
                 ai_path, aik_attributes) -> None:
        
        self._logs = []
        self._config = FAPIConfig(temp_dirs=False, profile_name=profile_name,
                                  profile_dir=profile_dir, user_dir=user_dir,
                                  system_dir=system_dir, log_dir=log_dir,
                                  ek_cert_less="yes")
        self._ctx = FAPI()

        self._nv_time_path = nv_time_path
        self._nv_sign_path = nv_sign_path
        self._nv_epoch_path = nv_epoch_path

        self._epoch_limit = None
        self._sign_key = f"/{self._ctx.config.profile_name}{"/HS/SRK/key_sign"}" # Keys for commit signing
        self._ai_key =  f"/{self._ctx.config.profile_name}{ai_path}"   # Keys to sign epoch
        self._aik_attributes = aik_attributes

    def setup(self, do_provision=False, create_nv=False, create_aik=False, create_sign=False) -> bool:

        if not self._ctx:
            print("TPM context not created.")

        # Provision the TPM based on the fapi configuration given in the constructor
        if do_provision:
            self._ctx.provision()

        if create_nv:
                self._ctx.create_nv(path=self._nv_time_path, size=256)
                self._ctx.create_nv(path=self._nv_sign_path, size=256)
                self._ctx.create_nv(path=self._nv_epoch_path, size=256)

        if create_aik:
            self._create_ak()

        return True

    def _create_ak(self) -> bool:
        success = self._ctx.create_key(path=self._ai_key, type_=self._aik_attributes)

        # self._ctx.create_key(path="/HS/SRK/key_aik", type_="sign, restricted, 0x81000005")
        if success:
            print("Create aik successfully.")
            return success
        
        print("Could not create aik.")
        return success
    
    def close(self, do_delete=False) -> None:

        if do_delete:
            self._ctx.delete("/")

        if self._ctx:
            self._ctx.close()
 
        if self._config:
            self._config.close()

    def log(self, data):

        # Create a log model to store the secure log fileds

        current_log = LogModel()
        current_log.set_data(data.decode())

        pcr_digest, _ = self._ctx.pcr_read(Logger.PCR)
        current_log.set_previous_pcr(pcr_digest)
        
        # Extend data in pcr
        self._ctx.pcr_extend(Logger.PCR, data)
        pcr_digest, _ = self._ctx.pcr_read(Logger.PCR)
        current_log.set_pcr(pcr_digest)

        # Sign the pcr
        signature, _, _ = self._ctx.sign(path=self._sign_key, digest=pcr_digest)
        current_log.set_signature(signature)

        if len(self._logs) == 0:
            current_log.set_new_chain(True)
        else:
            current_log.set_new_chain(False)

        # Update the in memory logs
        self._logs.append(current_log)
        return current_log
        
    def create_log_epoch(self):

        # Cannot call on empty list of logs
        if len(self._logs) == 0:
            return None
        
        current_epoch = EpochModel()
        current_epoch.set_commits(self._logs)

        import pickle

        as_bytes = pickle.dumps(self._logs)
        digest = sha256(as_bytes)
        signature, _, _ = self._ctx.sign(path=self._sign_key, digest=digest)
        current_epoch.set_aik_signature(signature)

        return current_epoch

    def verify_log(self):
        pass


if __name__ == '__main__':

    # Load the project config
    config = json_to_dict("config.json")

    controller = Logger(config["profile_name"], 
                        config["profile_dir"],
                        config["user_dir"], 
                        config["system_dir"], 
                        config["log_dir"],
                        config["nv_time_path"],
                        config["nv_sign_path"],
                        config["nv_epoch_path"],
                        config["ai_key"],
                        config["aik_attributes"])
    
    controller.setup()

    commit = controller.log(b"\x11" * 100)
    pprint.pprint(commit.as_dict())

    commit = controller.log(b"\x21" * 100)
    pprint.pprint(commit.as_dict())

    commit = controller.log(b"\x31" * 100)
    pprint.pprint(commit.as_dict())

    epoch = controller.create_log_epoch()
    pprint.pprint(epoch.as_dict())
    
    controller.close()