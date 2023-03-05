import socket
import select
import rsa
import utils
import pickle
from utils import MessageTypes, HEADER_LENGTH
from utils import enc, dec
import time

from dotenv import load_dotenv
load_dotenv()
import os

HEADER_LENGTH = int(os.environ.get("HEADER_LENGTH"))

IP = "127.0.0.1"
PORT = 1234

# Create a socket
# socket.AF_INET - address family, IPv4, some otehr possible are AF_INET6, AF_BLUETOOTH, AF_UNIX
# socket.SOCK_STREAM - TCP, conection-based, socket.SOCK_DGRAM - UDP, connectionless, datagrams, socket.SOCK_RAW - raw IP packets
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# SO_ - socket option
# SOL_ - socket option level
# Sets REUSEADDR (as a socket option) to 1 on socket
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Bind, so server informs operating system that it's going to use given IP and port
# For a server using 0.0.0.0 means to listen on all available interfaces, useful to connect locally to 127.0.0.1 and remotely to LAN interface IP
server_socket.bind((IP, PORT))

# This makes server listen to new connections
server_socket.listen()

# List of sockets for select.select()
sockets_list = [server_socket]

# List of connected clients - socket as a key, user header and name as data
clients = {}

socket_to_pem_key = {}
pem_key_to_socket = {}
str_to_obj_keys = {}

f = open("./keys/private.txt", "r")
server_private_key = rsa.PrivateKey.load_pkcs1(f.read().encode('utf8'))
f.close()

print(f'Listening for connections on {IP}:{PORT}...')

def send_new_public_key(new_pem_key):
    for str_key, current_socket in pem_key_to_socket.items():
        print('socket')
        print(current_socket)
        message_object = {'type': MessageTypes.ADD_PUBLIC_KEY, 'key': new_pem_key}
        utils.send_object_to_socket(message_object, current_socket, str_to_obj_keys[str_key])
        

def send_list_of_public_keys(client_socket, obj_key):
  
  print('started send_list_of_public_keys')
  
  for str_key, _ in str_to_obj_keys.items():
    print(str_key)
    message_object = {'type': MessageTypes.ADD_PUBLIC_KEY, 'key': str_key}
    time.sleep(1)
    utils.send_object_to_socket(message_object, client_socket, obj_key)
  print('finished send_list_of_public_keys')

# Handles message receiving
def receive_message(client_socket):

    try:

        # Receive our "header" containing message length, it's size is defined and constant
        message_header = client_socket.recv(HEADER_LENGTH)
        print(message_header)

        # If we received no data, client gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
        if not len(message_header):
            return False

        print('here')
        # Convert header to int value
        message_length = int(message_header.decode('utf-8').strip())

        print(message_length)

        encrypted_data = client_socket.recv(message_length)

        print(encrypted_data)

        decrypted_data = utils.decrypt(server_private_key, encrypted_data)

        print(decrypted_data)

        message_object = pickle.loads(decrypted_data)

        
        

        # Return an object of message header and message data
        return message_object

    except:

        # If we are here, client closed connection violently, for example by pressing ctrl+c on his script
        # or just lost his connection
        # socket.close() also invokes socket.shutdown(socket.SHUT_RDWR) what sends information about closing the socket (shutdown read/write)
        # and that's also a cause when we receive an empty message
        return False

while True:
    read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)

    for notified_socket in read_sockets:
        print(notified_socket)

        if notified_socket == server_socket:

            client_socket, client_address = server_socket.accept()
            print(client_socket)
            public_key = receive_message(client_socket)
            print(public_key)

            # If False - client disconnected before he sent his name
            if public_key is False:
                continue

            # Add accepted socket to select.select() list
            sockets_list.append(client_socket)

            # Also save username and username header
            clients[client_socket] = public_key
            

            # print('Encrypted user data ' + str(user['data']))
            user_pem_public_key_str = public_key['key']


            user_public_key = rsa.PublicKey.load_pkcs1(enc(user_pem_public_key_str), 'PEM')

            print(user_public_key)

            send_list_of_public_keys(client_socket, user_public_key)

            send_new_public_key(user_pem_public_key_str)

            socket_to_pem_key[client_socket] = user_pem_public_key_str
            pem_key_to_socket[user_pem_public_key_str] = client_socket
            str_to_obj_keys[user_pem_public_key_str] = user_public_key

            print(pem_key_to_socket)


            print('Accepted new connection from {}:{}'.format(*client_address))



        # Else existing socket is sending a message
        else:

            # Receive message
            message_object = receive_message(notified_socket)
            print(message_object)

            # If False, client disconnected, cleanup
            if message_object is False:
                print('Closed connection from: {}'.format(2))

                # Remove from list for socket.socket()
                sockets_list.remove(notified_socket)

                pem_key = socket_to_pem_key[notified_socket]

                del str_to_obj_keys[pem_key]

                del pem_key_to_socket[pem_key]

                del socket_to_pem_key[notified_socket]

                # Remove from our list of users
                del clients[notified_socket]

                continue
            
            message_type = message_object['type']

            print(message_object)

            if message_type == MessageTypes.CHAT_MESSAGE:
                dest_key = message_object['public-key']
                bytes_remaining = int(message_object['byte-length'])
                encrypted_data = client_socket.recv(bytes_remaining)
                pem_key_to_socket[dest_key].send(encrypted_data)


            # Old

    # It's not really necessary to have this, but will handle some socket exceptions just in case
    for notified_socket in exception_sockets:

        # Remove from list for socket.socket()
        sockets_list.remove(notified_socket)

        # Remove from our list of users
        del clients[notified_socket]



    