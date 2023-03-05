import socket
import select
import errno
import tkinter
from tkinter import scrolledtext, simpledialog
import threading
import pickle
from enum import Enum
from dotenv import load_dotenv
import rsa
from utils import MessageTypes, HEADER_LENGTH
import utils
from utils import enc, dec
import time

KEY_LENGTH = 2048

IP = "127.0.0.1"
PORT = 1234


class Client:
    def __init__(self) -> None:

      self.str_to_obj_keys = {}

      f = open("./keys/public.txt", "r")
      self.server_public_key = rsa.PublicKey.load_pkcs1(f.read().encode('utf8'))
      f.close()

     
      self.public_key, self.private_key = rsa.newkeys(KEY_LENGTH)
      self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.socket.connect((IP, PORT))
      print(self.socket)
      self.socket.setblocking(False)
      
      self.str_public_key = dec(self.public_key.save_pkcs1('PEM'))
      print('self')
      print(self.str_public_key)

      self.prompt_username()

      public_key_object = {'type': MessageTypes.ADD_PUBLIC_KEY, 'key': self.str_public_key}
      
      utils.send_object_to_socket(public_key_object, self.socket, self.server_public_key)
      self.start_threads()
      #self.socket.send(username_header + username)
      #self.send_encrypted_message(public_key_message)
      # print(encrypted_public_key)

      


    def send_to_all(self, message):
       print('in send_to_all')
       print('current public keys')
       print(self.str_to_obj_keys)
       peer_message = {'type': MessageTypes.CHAT_MESSAGE,'username': self.username, 'message': message}
       pickled_message = pickle.dumps(peer_message)

       for str_key, object_key in self.str_to_obj_keys.items():
          message_body = utils.encrypt(object_key, pickled_message)
          destination_message = utils.wrap_body(message_body)
          self.encrypt_and_send_forward_server(str_key, destination_message)

    def encrypt_and_send_forward_server(self, destination_key, destination_encr_message):
       server_message = {'type': MessageTypes.CHAT_MESSAGE, 'public-key': destination_key, 'byte-length': len(destination_encr_message) }
       server_msg_bytes = pickle.dumps(server_message)
       encrypted_server_msg = utils.encrypt(self.server_public_key,server_msg_bytes)
       wrapped_server_msg = utils.wrap_body(encrypted_server_msg)
       self.socket.send(wrapped_server_msg + destination_encr_message)
       
    def send_encrypted_message(self, encoded_msg):
       
       self.socket.send(encoded_msg)

    def receive_encrypted_message(self):
       pass

    def gui_loop(self):
      self.win = tkinter.Tk()
      b_color = "lightgray"

      self.win.configure(bg=b_color)

      self.chat_label = tkinter.Label(self.win, text="Chat:", bg=b_color)
      self.chat_label.config(font=("Arial", 12))
      self.chat_label.pack(padx=20, pady=5)

      self.text_area = scrolledtext.ScrolledText(self.win)
      self.text_area.pack(padx=20, pady=5)
      self.text_area.config(state="disabled")

      self.message_label = tkinter.Label(self.win, text="Message:", bg=b_color)
      self.message_label.config(font=("Arial", 12))
      self.message_label.pack(padx=20, pady=5)

      self.input_area = tkinter.Text(self.win, height=3)
      self.input_area.pack(padx=20, pady=5)

      self.send_button = tkinter.Button(self.win, text="Send", command=self.send_message)
      self.send_button.config(font=("Arial", 12))
      self.send_button.pack(padx=20, pady=5)

      self.gui_done = True

      self.win.protocol("WM_DELETE_WINDOW", self.stop)

      self.win.mainloop()

    def prompt_username(self):
        msg = tkinter.Tk()
        msg.withdraw()
        self.username = simpledialog.askstring("Username", "Enter your username", parent=msg)
        self.gui_done = False
        self.running = True

    def send_message(self):
      message = f'{self.input_area.get("1.0", "end")}'
      self.send_to_all(message)
      self.input_area.delete('1.0', 'end')

      # below old
      
      
      ## CHANGE THIS!
      #encrypted_message = utils.encrypt(self.server_public_key, encoded_message)
      #self.send_encrypted_message(utils.wrap_body(encrypted_message))
      
    
    def generate_encrypted_message(self, headers, message_body):
       pass
    
    def append_message(self, username, message):
      self.text_area.config(state="normal")
      self.text_area.insert('end', f'{username} > {message}')

      self.text_area.config(state="disable")
    
    def receive_messages(self):
      while self.running:
        try:
            header = self.socket.recv(HEADER_LENGTH)
            print('header')
            print(header)
            # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
            if not len(header):
                print('Connection closed by the server')
                self.stop()
            elif self.gui_done:
              # Convert header to int value
              encrypted_length = int(header.decode('utf-8').strip())

              

              encrypted_message = self.socket.recv(encrypted_length)

              print(encrypted_message)

              pickled_message = utils.decrypt(self.private_key, encrypted_message)

              print(pickled_message)

              message_object = pickle.loads(pickled_message)

              message_type = message_object['type']

              #print(message_type)

              print(message_object)

              if message_type == MessageTypes.ACTIVE_PUBLIC_KEYS:
                for key in message_object['keys']:
                   pass
                  #self.peer_pem_to_byte_keys.add(key)
              elif message_type == MessageTypes.ADD_PUBLIC_KEY:
                print(message_object)
                key_pem = message_object['key']
                key_object = rsa.PublicKey.load_pkcs1(enc(key_pem))
                self.str_to_obj_keys[key_pem] = key_object
                print('saved!')
                print(key_pem)
              elif message_type == MessageTypes.REMOVE_PUBLIC_KEY:
                 key = message_object['key']
                 del self.str_to_obj_keys[key]
              elif message_type == MessageTypes.CHAT_MESSAGE:
                 self.append_message(message_object['username'], message_object['message'])


        except IOError as e:
        # This is normal on non blocking connections - when there are no incoming data error is going to be raised
        # Some operating systems will indicate that using AGAIN, and some using WOULDBLOCK error code
        # We are going to check for both - if one of them - that's expected, means no incoming data, continue as normal
        # If we got different error code - something happened
            if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                print('Reading error1: {}'.format(str(e)))
                self.stop()

            # We just did not receive anything
            continue

        except Exception as e:
            # Any other exception - something happened, exit
            print('Reading error2: '.format(str(e)))
            self.stop()
    
    def start_threads(self):
      tk_thread = threading.Thread(target=self.gui_loop)
      receiver_thread = threading.Thread(target=self.receive_messages)

      tk_thread.start()
      receiver_thread.start()

    def stop(self):
        self.running = False
        self.win.destroy()
        self.socket.close()
        exit(0)

Client()