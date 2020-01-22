import time
import socket
import sys
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify

# Real time chat logic
print("Setting Up the Server. Please wait... :)")
time.sleep(3)

# Getting the hostname, IP Address from socket and set Port
soc = socket.socket()
host_name = socket.gethostname()
ip = socket.gethostbyname(host_name)
port = 1234
soc.bind((host_name, port))

print(host_name, "({})".format(ip))
name = input("\nEnter name: ")
soc.listen(1) # Try to locate using socket

print("\n--------------------------------- Config ---------------------------------")
print("Waiting for incoming connections...")
connection, addr = soc.accept()

print("Received connection from ", addr[0], "(", addr[1], ")")
print("Connection Established. Connected From: {}, ({})".format(addr[0], addr[0]))
print("----------------------------------------------------------------------\n")

# Get a connection from client side
client_name = connection.recv(1024)
client_name = client_name.decode()

print("--------------------------------- Info ---------------------------------")
print(client_name + " has connected.")
print("Input quit to leave the chat room")
connection.send(name.encode())

# Encryption & Decryption logic
# Function for generating public and private key for server side
def create_keys():
   print("\nCreating public and private keys...Please wait...")

   private_key = RSA.generate(1024) # Generating private key (RsaKey object) of key length of 1024 bits
   public_key = private_key.publickey() # Generating the public key (RsaKey object) from the private key

   # Converting the RsaKey objects to string
   private_pem = private_key.export_key().decode()
   public_pem = public_key.export_key().decode()

   # Writing down the private and public keys to 'pem' files
   with open('private_server_key.pem', 'w') as pr:
      pr.write(private_pem)
   with open('public_server_key.pem', 'w') as pu:
      pu.write(public_pem)

   # Importing keys from files, converting it into the RsaKey object
   pr_key = RSA.import_key(open('private_server_key.pem', 'r').read())
   pu_key = RSA.import_key(open('public_server_key.pem', 'r').read())

   print("Successfully created public and private keys for server side :)")
   print("----------------------------------------------------------------------\n")

def read_public_key():
   pu_key = RSA.import_key(open('public_server_key.pem', 'r').read())
   return pu_key

def read_private_key():
   pr_key = RSA.import_key(open('private_server_key.pem', 'r').read())
   return pr_key

def encrypt_message(pu_key, message):
   # Instantiating PKCS1_OAEP object with the public key for encryption
   cipher = PKCS1_OAEP.new(key = pu_key)

   # Encrypting the message with the PKCS1_OAEP object
   encrypted_message = cipher.encrypt(bytes(message, "utf-8"))
   return encrypted_message

def decrypt_message(pr_key, cipher):
   # Instantiating PKCS1_OAEP object with the private key for decryption
   decrypt = PKCS1_OAEP.new(key = pr_key)

   # Decrypting the message with the PKCS1_OAEP object
   decrypted_message = decrypt.decrypt(cipher)
   return decrypted_message

create_keys()
is_over = False

# Inicijalno slanje pu_key na pocetku rada socketa
if not is_over:
   pu_key = read_public_key()
   connection.send(pu_key.publickey().exportKey(format = 'PEM', passphrase = None, pkcs = 1))
   is_over = True

pu_key_client = RSA.importKey(connection.recv(1024), passphrase = None)

print("--------------------------------- Chat Room ---------------------------------")
while True:
   message = input("Me > ")
   if message == "quit":
      message = "Bye! :)"
      print(message)
      break

   # Slanje poruka
   encrypted_message = encrypt_message(pu_key_client, message)
   connection.send(encrypted_message)

   # Primanje poruka
   message = connection.recv(1024)
   pr_key = read_private_key()
   decrypted_message = decrypt_message(pr_key, message)
   message = decrypted_message.decode("utf-8")
   print(client_name, ">", message)