
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