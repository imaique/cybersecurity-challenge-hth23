from enum import Enum
import rsa

class MessageTypes(Enum):
    NEW_CONNECTION = 1
    PASSWORD = 2
    CHAT_MESSAGE = 3
    USERNAME = 4

def encrypt(public_key, byte_data):
    return rsa.encrypt(byte_data, public_key)
