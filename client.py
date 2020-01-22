import time
import socket
import sys
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

# 1. Socket Logic
print("Setting Up the Client Server. Please wait... :)")
time.sleep(3)

# Get the hostname, IP Address from socket and set Port
soc = socket.socket()
shost = socket.gethostname()
ip = socket.gethostbyname(shost)

# Get information to connect with the server
print(shost, "({})".format(ip))
server_host = input("\nEnter server\'s IP address:")
while server_host != ip:
   server_host = input("\nEnter your Computer\'s IP address:")

name = input("Enter Client\'s name: ")
port = 1234

print("\n--------------------------------- Config ---------------------------------")
print("Trying to connect to the server: {}, ({})".format(server_host, port))
time.sleep(3)
soc.connect((server_host, port))
print("Successfully Connected!")
print("----------------------------------------------------------------------\n")

soc.send(name.encode())
server_name = soc.recv(1024)
server_name = server_name.decode()
print("--------------------------------- Info ---------------------------------")
print("{} has joined...".format(server_name))
print("Enter quit to exit.")

# 2. Encryption / Decryption Logic
# Creating private and public key for client side
def create_keys():
   print("\nCreating public and private keys...Please wait...")
   private_key = RSA.generate(1024)
   public_key = private_key.publickey()
   private_pem = private_key.export_key().decode()
   public_pem = public_key.export_key().decode()
   with open('private_client_key.pem', 'w') as pr:
      pr.write(private_pem)
   with open('public_client_key.pem', 'w') as pu:
      pu.write(public_pem)

   pr_key = RSA.import_key(open('private_client_key.pem', 'r').read())
   pu_key = RSA.import_key(open('public_client_key.pem', 'r').read())

   print("Successfully created public and private keys for client side :)")
   print("----------------------------------------------------------------------\n")

def read_public_key():
   pu_key = RSA.import_key(open('public_client_key.pem', 'r').read())
   return pu_key

def read_private_key():
   pr_key = RSA.import_key(open('private_client_key.pem', 'r').read())
   return pr_key

def encrypt_message(pu_key, message):
   cipher = PKCS1_OAEP.new(key = pu_key)
   cipher_text = cipher.encrypt(bytes(message, "utf-8"))
   return cipher_text

def decrypt_message(pr_key, cipher_text):
   decrypt = PKCS1_OAEP.new(key = pr_key)
   decrypted_message = decrypt.decrypt(cipher_text)
   return decrypted_message

create_keys()
is_over = False

# Dobivanje pu_key od server side
pu_key_server = RSA.importKey(soc.recv(1024), passphrase = None)

# Inicijalno slanje pu_key na pocetku rada socketa
if not is_over:
   pu_key = read_public_key()
   soc.send(pu_key.publickey().exportKey(format = 'PEM', passphrase = None, pkcs = 1))
   is_over = True

print("--------------------------------- Chat Room ---------------------------------")
while True:
   message = soc.recv(1024)

   # Primanje poruka
   pr_key = read_private_key()
   decrypted_message = decrypt_message(pr_key, message)
   message = decrypted_message.decode("utf-8")
   print(server_name, ">", message)

   message = input(str("Me > "))
   if message == "quit":
      message = server_name + " has left the chat room."
      print(message)
      break

   # Slanje poruka
   encrypted_message = encrypt_message(pu_key_server, message)
   soc.send(encrypted_message)