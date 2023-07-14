import socket
import os
import sys
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def client():
    # Server Information
    serverName = input("Enter the server IP or name: ")
    serverPort = 13000

    # Open server public key from file
    with open("server_public.pem", "rb") as file:
        server_public = file.read()
    # Generate Cyphering Block
    server_pubkey = RSA.import_key(server_public)
    cipher_rsa_en = PKCS1_OAEP.new(server_pubkey)

    # Open client private key from file
    with open("client1_private.pem", "rb") as file:
        client_private = file.read()
    # Generate decrypting block
    client_privkey = RSA.import_key(client_private)
    cipher_rsa_dec = PKCS1_OAEP.new(client_privkey)

    # Create client socket that useing IPv4 and TCP protocols
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print("Error in client socket creation:", e)
        sys.exit(1)

    try:
        # Client connect with the server
        clientSocket.connect((serverName, serverPort))

        # Client gets user info
        username = input("Enter your username: ")
        password = input("Enter your password: ")

        # Client sends user info
        userEncrypted = cipher_rsa_en.encrypt(username.encode("ascii"))
        clientSocket.send(userEncrypted)

        passEncrypted = cipher_rsa_en.encrypt(password.encode("ascii"))
        clientSocket.send(passEncrypted)

        # Client receives login response from server
        loginResponse = clientSocket.recv(2048)
        try:
            loginResponseString = loginResponse.decode("ascii")
        except:
            loginResponseString = "Valid user"

        if loginResponseString == "Invalid username or password":
            # Terminate the connection
            print("Invalid username or password.\nTerminating.")
            clientSocket.close()
            sys.exit(0)

        # Server has sent symmetric key, decrypt and store it
        sym_key = cipher_rsa_dec.decrypt(loginResponse)
        # print(sym_key.decode('ascii'))

        # Create new cipher from symmetric key
        cipher_symmetric = AES.new(sym_key, AES.MODE_ECB)

        # Send OK response message to server
        okMsg = "OK"
        okMsgEncrypted = cipher_symmetric.encrypt(pad(okMsg.encode("ascii"), 16))
        clientSocket.send(okMsgEncrypted)

        # Start menu loop
        menuChoice = "0"
        while menuChoice != "4":
            # Receive menu message from server
            menuMsgEncrypted = clientSocket.recv(2048)
            menuMsgPadded = cipher_symmetric.decrypt(menuMsgEncrypted)
            menuMsg = unpad(menuMsgPadded, 16).decode("ascii")
            menuChoice = input(menuMsg)

            # Send menu choice to server
            menuChoiceEncrypted = cipher_symmetric.encrypt(
                pad(menuChoice.encode("ascii"), 16)
            )
            clientSocket.send(menuChoiceEncrypted)

        # Client terminate connection with the server
        clientSocket.close()

    except socket.error as e:
        print("An error occured:", e)
        clientSocket.close()
        sys.exit(1)


# ----------
client()
