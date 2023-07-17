import socket
import os
import sys
import random
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

###############################################################################


class Server:
    def __init__(self):
        self.serverPort = 13000
        self.serverSocket = None
        self.server_public = None
        self.server_pubkey = None
        self.cipher_rsa_en_server = None
        self.server_private = None
        self.server_privkey = None
        self.cipher_rsa_dec_server = None
        self.cipher_symmetric = None

    def create_server_socket(self):
        """
        Create server socket that uses IPv4 and TCP protocols
        Paremeters: None
        Return: None
        """
        try:
            self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as e:
            print("Error in server socket creation:", e)
            sys.exit(1)
        return

    def bind_server_socket(self):
        """
        Associate 13000 port number to the server socket
        Paremeters: None
        Return: None
        """
        try:
            self.serverSocket.bind(("", self.serverPort))
        except socket.error as e:
            print("Error in server socket binding:", e)
            sys.exit(1)

        print("The server is ready to accept connections")
        return

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
        self.cipher_rsa_en_server = PKCS1_OAEP.new(self.server_pubkey)
        return

    def fill_server_private(self):
        """
        Fill server private key from file
        Paremeters: None
        Return: None
        """
        # Open server private key from file
        with open("server_private.pem", "rb") as file:
            self.server_private = file.read()
        # Generate decrypting block
        self.server_privkey = RSA.import_key(self.server_private)
        self.cipher_rsa_dec_server = PKCS1_OAEP.new(self.server_privkey)
        return

    def server_loop(self):
        self.serverSocket.listen(5)

        while 1:
            try:
                # Server accepts client connection
                self.connectionSocket, addr = self.serverSocket.accept()

                self.fill_server_public()
                self.fill_server_private()

                pid = os.fork()

                # If it is a client process
                if pid == 0:
                    self.serverSocket.close()

                    # Receive user info from client
                    userEncrypted = self.connectionSocket.recv(2048)
                    print("THIS IS A VERYY LONG STRING")
                    username = self.cipher_rsa_dec_server.decrypt(userEncrypted)
                    username = username.decode("ascii")

                    passEncrypted = self.connectionSocket.recv(2048)
                    print("107")
                    password = self.cipher_rsa_dec_server.decrypt(passEncrypted)
                    password = password.decode("ascii")

                    # Check against json file to determine if valid user
                    validUser = 0
                    f = open("user_pass.json")
                    userdata = json.load(f)

                    for user in userdata:
                        if user == username:
                            if password == userdata[username]:
                                validUser = 1

                    f.close()

                    if validUser == 1:
                        # Create sym key and send
                        keyLen = 256
                        sym_key = get_random_bytes(int(keyLen / 8))

                        # Generate Cyphering Block
                        self.cipher_symmetric = AES.new(sym_key, AES.MODE_CBC)

                        # encrypt sym key with server public key
                        clientPubFilename = username + "_public.pem"
                        with open(clientPubFilename, "rb") as file:
                            client_public = file.read()
                        client_pubkey = RSA.import_key(client_public)
                        cipher_rsa_en_client = PKCS1_OAEP.new(client_pubkey)

                        print("REEE")

                        symEncrypted = cipher_rsa_en_client.encrypt(sym_key)

                        print("REEE")

                        self.connectionSocket.send(symEncrypted)

                        print(
                            f"Connection Accepted and Symmetric Key Generated for client: {username}"
                        )

                        # Receive OK Msg from Client
                        print("151")
                        okMsgEncrypted = self.connectionSocket.recv(2048)
                        print("THIS IS A VERY LONG STRING AS WELL")
                        okPadded = self.cipher_symmetric.decrypt(okMsgEncrypted)
                        print("I AM DOING THE SAME THING FOR 155 JUST TO BE SAFE")
                        # okMsg = unpad(okPadded, 16)

                        # Start menu loop
                        menuChoice = "0"
                        while menuChoice != "4":
                            menuMsg = (
                                "Select the operation:\n1) Create and send an email\n2) Display the inbox\n"
                                "3) Display the email contents\n4) Terminate the connection\nchoice: "
                            )
                            print(self.cipher_symmetric)
                            print(menuChoice)
                            menuMsgEncrypted = self.cipher_symmetric.encrypt(
                                pad(menuMsg.encode("ascii"), 16)
                            )
                            print(menuMsgEncrypted)
                            print("171")

                            self.connectionSocket.send(menuMsgEncrypted)

                            # Receive menu choice from clientf
                            menuChoiceEncrypted = self.connectionSocket.recv(2048)

                            menuChoicePadded = self.cipher_symmetric.decrypt(
                                menuChoiceEncrypted
                            )
                            print("REEE")

                            menuChoice = unpad(menuChoicePadded, 16).decode("ascii")

                    if validUser == 0:
                        # Invalid user, send termination notice
                        invalidMsg = "Invalid username or password"
                        self.connectionSocket.send(invalidMsg.encode("ascii"))
                        print(
                            f"The received client information: {username} is invalid (Connection Terminated)."
                        )

                    self.connectionSocket.close()

                    return

            except socket.error as e:
                print("An error occured:", e)
                self.serverSocket.close()
                sys.exit(1)

            # Parent doesn't need this connection
            self.connectionSocket.close()


###############################################################################


def main():
    server = Server()
    server.create_server_socket()
    server.bind_server_socket()
    server.server_loop()


###############################################################################
if __name__ == "__main__":
    main()
