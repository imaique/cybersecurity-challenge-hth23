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
from utils import MessageTypes
import utils
load_dotenv()

import os

HEADER_LENGTH = int(os.environ.get("HEADER_LENGTH"))

IP = "127.0.0.1"
PORT = 1234


class Client:
    def __init__(self) -> None:
      f = open("./keys/public.txt", "r")

      self.server_public_key = rsa.PublicKey.load_pkcs1(f.read().encode('utf8'))

      self.public_key, self.private_key = rsa.newkeys(2048)
      self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.socket.connect((IP, PORT))
      self.socket.setblocking(False)

      msg = tkinter.Tk()
      msg.withdraw()

      self.username = simpledialog.askstring("Username", "Enter your username", parent=msg)

      self.gui_done = False
      self.running = True

      username = self.username.encode('utf-8')
      username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
      #self.socket.send(username_header + username)
      self.send_encrypted_message(username_header + username)

      tk_thread = threading.Thread(target=self.gui_loop)
      receiver_thread = threading.Thread(target=self.receive_messages)

      tk_thread.start()
      receiver_thread.start()

    def encrypt_and_send(self, message_type, message):
       plain_message = {message_type: message_type, message: message}
       pickled_message = pickle.dumps(plain_message)
       encrypted_message = utils.encrypt(self.server_public_key, pickled_message)
       message_len = len(encrypted_message)
       byte_header = bytes(f"{message_len:<{HEADER_LENGTH}}".encode('utf-8'))
       complete_message = byte_header + encrypted_message
       self.socket.send(complete_message)

    
       
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

    def send_message(self):
      message = f'{self.input_area.get("1.0", "end")}'
      message = message.encode('utf-8')
      message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')

      self.send_encrypted_message(message_header + message)
      self.input_area.delete('1.0', 'end')
    
    def generate_encrypted_message(self, headers, message_body):
       
       pass
    
    def receive_messages(self):
      while self.running:
        try:
            username_header = self.socket.recv(HEADER_LENGTH)
            # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
            if not len(username_header):
                print('Connection closed by the server')
                self.stop()
            elif self.gui_done:
              # Convert header to int value
              username_length = int(username_header.decode('utf-8').strip())

              # Receive and decode username
              username = self.socket.recv(username_length).decode('utf-8')

              # Now do the same for message (as we received username, we received whole message, there's no need to check if it has any length)
              message_header = self.socket.recv(HEADER_LENGTH)
              message_length = int(message_header.decode('utf-8').strip())
              message = self.socket.recv(message_length).decode('utf-8')

              self.text_area.config(state="normal")
              self.text_area.insert('end', f'{username} > {message}')

              self.text_area.config(state="disable")


        except IOError as e:
        # This is normal on non blocking connections - when there are no incoming data error is going to be raised
        # Some operating systems will indicate that using AGAIN, and some using WOULDBLOCK error code
        # We are going to check for both - if one of them - that's expected, means no incoming data, continue as normal
        # If we got different error code - something happened
            if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                print('Reading error: {}'.format(str(e)))
                self.stop()

            # We just did not receive anything
            continue

        except Exception as e:
            # Any other exception - something happened, exit
            print('Reading error: '.format(str(e)))
            self.stop()

    def stop(self):
        self.running = False
        self.win.destroy()
        self.socket.close()
        exit(0)

Client()