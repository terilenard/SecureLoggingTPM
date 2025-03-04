import pprint

from utils import sha256


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
    
    
    def __str__(self):
        return self.data + str(self.pcr) + str(self.signature)

    def __hash__(self):

        to_hash = b''

        if not isinstance(self.data, bytes):
            to_hash += self.data.encode()
        else:
            to_hash += self.data

        if not isinstance(self.pcr, bytes):
            to_hash += self.pcr.encode()
        else:
            to_hash += self.pcr

        if not isinstance(self.signature, bytes):
            to_hash += self.signature.encode()
        else:
            to_hash += self.signature

        digest = sha256(to_hash)
        int_digest = int.from_bytes(digest, 'big')
        
        return int_digest 

    def __eq__(self,other):
        return self.data == other.data and self.pcr == other.pcr and self.signature == other.signature


if __name__ == "__main__":
    
    log1 = LogModel().set_data("a").set_pcr("pcr".encode()).set_signature("aaa".encode()).set_previous_pcr("pcr_prev")
    log2 = LogModel().set_data("a").set_pcr("pcr".encode()).set_signature("aaa".encode()).set_previous_pcr("pcr_prev")
    log3 = LogModel().set_data("b").set_pcr("pcr".encode()).set_signature("aaa".encode()).set_previous_pcr("pcr_prev")

    assert(log1 == log2)
    assert(log1 != log3)
    assert(log2 != log3)
    assert(hash(log1) == hash(log2))
    assert(hash(log1) != hash(log3))
