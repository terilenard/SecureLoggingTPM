from collections import Counter
from log_model import LogModel


class EpochModel(object):

    def __init__(self):

        self.commits = None
        self.aik_signature = None

    def set_commits(self, commits):
        self.commits = commits
        return self
    
    def set_aik_signature(self, signature):
        self.aik_signature = signature
        return self

    def as_dict(self):
        return {
            "commits": self.commits,
            "aik_signature": self.aik_signature,
        }
    def __eq__(self,other):
        return Counter(self) == Counter(other)


if __name__ == "__main__":
    log1 = LogModel().set_data("a").set_pcr("pcr".encode()).set_signature("aaa".encode()).set_previous_pcr("pcr_prev")
    log2 = LogModel().set_data("a").set_pcr("pcr".encode()).set_signature("aaa".encode()).set_previous_pcr("pcr_prev")
    log3 = LogModel().set_data("b").set_pcr("pcr".encode()).set_signature("aaa".encode()).set_previous_pcr("pcr_prev")

    logs = []
    logs.append(log1)
    logs.append(log2)
    logs.append(log3)

    epoch_model1 = EpochModel()
    epoch_model1.set_commits(logs)
    epoch_model1.set_aik_signature(b"123")

    epoch_model2 = EpochModel()
    epoch_model1.set_commits(logs)
    epoch_model1.set_aik_signature(b"123")

    assert(epoch_model1 == epoch_model2)