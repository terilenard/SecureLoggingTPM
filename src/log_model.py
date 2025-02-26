import pprint

class LogModel(object):

    def __init__(self):

        self.previous_pcr = None
        self.data = None
        self.pcr = None
        self.signature = None
        self.is_new_chain = False

    def set_previous_pcr (self, previous_pcr):
        self.previous_pcr = previous_pcr
        return self

    def set_data(self, data):
        self.data = data
        return self

    def set_pcr(self, pcr_digest):
        self.pcr = pcr_digest
        return self
    
    def set_signature(self, signature):
        self.signature = signature
        return self
    
    def set_new_chain(self, is_new):
        self.is_new_chain = is_new
        return self

    def as_dict(self):
        return {
            "previous_pcr": self.previous_pcr,
            "data": self.data,
            "pcr": self.pcr,
            "signature": self.signature,
            "is_new_chain": self.is_new_chain
        }


if __name__ == "__main__":
    
    log = LogModel().set_data("a").set_pcr("pcr").set_signature("aaa").set_previous_pcr("pcr_prev")

    pprint.pprint(log.as_dict())