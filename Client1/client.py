import socket
import os
import sys
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


###############################################################################
class Client:
    def __init__(self, serverName="127.0.0.1"):
        # Server Information
        self.serverName = serverName
        self.serverPort = 13000
        self.server_public = None
        self.server_pubkey = None
        self.cipher_rsa_en = None
        # Client Information
        self.clientSocket = None
        self.client_private = None
        self.client_privkey = None
        self.cipher_rsa_dec = None
        self.loginResponse = None
        # Symmetric Key
        self.cipher_symmetric = None

    # LOGGING IN

    def fill_server_public(self):
        """
        Fill server public key from file
        Paremeters: None
        Return: None
        """
        # Open server public key from file
        with open("server_public.pem", "rb") as file:
            self.server_public = file.read()
        # Generate Cyphering Block
        self.server_pubkey = RSA.import_key(self.server_public)
        self.cipher_rsa_en = PKCS1_OAEP.new(self.server_pubkey)
        return

    def fill_client_private(self):
        """
        Fill client private key from file
        Paremeters: None
        Return: None
        """
        # Open client private key from file
        with open("client1_private.pem", "rb") as file:
            self.client_private = file.read()
        # Generate decrypting block
        self.client_privkey = RSA.import_key(self.client_private)
        self.cipher_rsa_dec = PKCS1_OAEP.new(self.client_privkey)
        return

    def create_client_socket(self):
        """
        Create client socket
        Paremeters: None
        Return: None
        """
        # Create client socket that useing IPv4 and TCP protocols
        try:
            self.clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as e:
            print("Error in client socket creation:", e)
            sys.exit(1)
        return

    def connect_to_server(self):
        """
        Connect to server
        Paremeters: None
        Return: None
        """
        # Client connect with the server
        self.clientSocket.connect((self.serverName, self.serverPort))
        return

    def send_user_info(self):
        """
        Send user info to server
        Paremeters: None
        Return: None
        """
        # Client gets user info
        username = input("Enter your username: ")
        password = input("Enter your password: ")

        # Client sends user info
        userEncrypted = self.cipher_rsa_en.encrypt(username.encode("ascii"))
        self.clientSocket.send(userEncrypted)

        passEncrypted = self.cipher_rsa_en.encrypt(password.encode("ascii"))
        self.clientSocket.send(passEncrypted)
        return

    def receive_user_info(self):
        """
        Receive user info from server
        Paremeters: None
        Return: None
        """
        loginResponse = self.clientSocket.recv(2048)
        try:
            loginResponseString = self.cipher_rsa_dec.decrypt(loginResponse)
        except:
            loginResponseString == "Valid User"
            self.loginResponse = loginResponse

        if loginResponseString == "Invalid username or password":
            # Terminate the connection
            print("Invalid username or password.\nTerminating.")
            self.clientSocket.close()
            sys.exit(0)

    def receive_symmetric_key(self):
        """
        Receive symmetric key from server
        Paremeters: None
        Return: None
        """
        # Server has sent symmetric key, decrypt and store it
        sym_key = self.cipher_rsa_dec.decrypt(self.loginResponse)

        # Create new cipher from symmetric key
        cipher_symmetric = AES.new(sym_key, AES.MODE_ECB)
        self.cipher_symmetric = cipher_symmetric

    def send_ok_response(self):
        """
        Send OK response to server
        Paremeters: None
        Return: None
        """
        # Send OK response message to server
        okMsg = "OK"
        okMsgEncrypted = self.cipher_symmetric.encrypt(pad(okMsg.encode("ascii"), 16))
        self.clientSocket.send(okMsgEncrypted)
        return

    def login(self):
        """
        Login to server
        Paremeters: None
        Return: None
        """
        self.fill_server_public()
        self.fill_client_private()
        self.create_client_socket()
        self.connect_to_server()
        self.send_user_info()
        self.receive_user_info()
        self.send_ok_response()
        return

    # MENU

    def menu_loop(self):
        """
        Menu loop
        Paremeters: None
        Return: None
        """
        menuChoice = "0"

        while menuChoice != "4":
            # Receive menu from server
            menuMsgEncrypted = self.clientSocket.recv(2048)
            menuMsgPadded = self.cipher_symmetric.decrypt(menuMsgEncrypted)
            menuMsg = unpad(menuMsgPadded, 16).decode("ascii")
            manuChoice = input(menuMsg)

            # Send menu choice to server
            self.send_menu_choice(self.cipher_symmetric, menuChoice)

        self.clientSocket.close()

    def send_menu_choice(self, menuChoice):
        """
        Send menu choice to server
        Paremeters: cipher_symmetric, menuChoice
        Return: None
        """
        menuChoiceEncrypted = self.cipher_symmetric.encrypt(
            pad(menuChoice.encode("ascii"), 16)
        )
        self.clientSocket.send(menuChoiceEncrypted)

        return


###############################################################################


def main():
    # TODO change this to input after testing
    client = Client("127.0.0.1")
    client.login()
    client.menu_loop()


###############################################################################

if __name__ == "__main__":
    main()
