from dataclasses import dataclass, asdict
import json

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

@dataclass
class Message:
    type: str
    payload: dict
    timestamp: int = None
    nonce: str = None
    hmac: str = None

    def to_json(self):
        return json.dumps(asdict(self))

    @staticmethod
    def from_json(json_str):
        return Message(**json.loads(json_str))
    
