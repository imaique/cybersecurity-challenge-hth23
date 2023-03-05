from enum import Enum
import rsa
import pickle

from dotenv import load_dotenv
load_dotenv()
import os

HEADER_LENGTH = int(os.environ.get("HEADER_LENGTH"))

class MessageTypes(Enum):
    NEW_CONNECTION = 1
    PASSWORD = 2
    CHAT_MESSAGE = 3
    USERNAME = 4
    ADD_PUBLIC_KEY = 5
    ACTIVE_PUBLIC_KEYS = 6
    REMOVE_PUBLIC_KEY = 7

def encrypt(public_key, byte_data):
    result = []
    for n in range(0,len(byte_data),245):
        part = byte_data[n:n+245]
        result.append( rsa.encrypt(part, public_key) )
    print(len(result),len(result[0]))
    return b''.join(result)

def decrypt(private_key, encrypted_data):
    result = []
    for n in range(0,len(encrypted_data),256):
        part = encrypted_data[n:n+256]
        result.append(rsa.decrypt(part, private_key))
    result = b''.join(result)
    return result

def wrap_body(message_body):
    message_len = len(message_body)
    byte_header = bytes(f"{message_len:<{HEADER_LENGTH}}".encode('utf-8'))
    complete_message = byte_header + message_body
    return complete_message

def send_object_to_socket(message_object, socket, public_key):
  bytes_data = pickle.dumps(message_object)
  encrypted_data = encrypt(public_key, bytes_data)
  message = wrap_body(encrypted_data)
  socket.send(message)


def RSA_decryption(RSA_content):
    result = []
    for n in range(0,len(RSA_content),256):
        part = RSA_content[n:n+256]
        result.append( rsa.decrypt(part, private_key).decode("ascii") )
    result = ''.join(result)
    return result

def dec(str):
    return str.decode('utf-8')

def enc(str):
    return str.encode('utf-8')