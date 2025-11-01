class KeyPair:
    def __init__(self, private_key=None, public_key=None):
        self.private_key = private_key
        self.public_key = public_key

class MessageNode:
    def __init__(self, content: bytes = b"", filename: str = None):
        self.content = content
        self.filename = filename

class SignatureNode:
    def __init__(self, data: bytes = b"", signature: bytes = b"", valid=False):
        self.data = data
        self.signature = signature
        self.valid = valid
