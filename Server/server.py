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


def server():
    # Server port
    serverPort = 13000

    # Create server socket that uses IPv4 and TCP protocols
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print("Error in server socket creation:", e)
        sys.exit(1)

    # Associate 13000 port number to the server socket
    try:
        serverSocket.bind(("", serverPort))
    except socket.error as e:
        print("Error in server socket binding:", e)
        sys.exit(1)

    print("The server is ready to accept connections")

    # The server can only have one connection in its queue waiting for acceptance
    serverSocket.listen(5)

    while 1:
        try:
            # Server accepts client connection
            connectionSocket, addr = serverSocket.accept()

            with open("server_public.pem", "rb") as file:
                server_public = file.read()
            # Generate Cyphering Block
            server_pubkey = RSA.import_key(server_public)
            cipher_rsa_en_server = PKCS1_OAEP.new(server_pubkey)

            # Open server private key from file
            with open("server_private.pem", "rb") as file:
                server_private = file.read()
            # Generate decrypting block
            server_privkey = RSA.import_key(server_private)
            cipher_rsa_dec_server = PKCS1_OAEP.new(server_privkey)

            pid = os.fork()

            # If it is a client process
            if pid == 0:
                serverSocket.close()

                # Receive user info from client
                userEncrypted = connectionSocket.recv(2048)
                username = cipher_rsa_dec_server.decrypt(userEncrypted)
                username = username.decode("ascii")

                passEncrypted = connectionSocket.recv(2048)
                password = cipher_rsa_dec_server.decrypt(passEncrypted)
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
                    # Valid user
                    # Create sym key and send
                    KeyLen = 256
                    sym_key = get_random_bytes(int(KeyLen / 8))
                    # Generate Cyphering Block for later usage
                    cipher_symmetric = AES.new(sym_key, AES.MODE_ECB)

                    # Encrypt the symmetric key and send to client with their respective public key
                    clientPubFilename = username + "_public.pem"
                    # Open client key file
                    with open(clientPubFilename, "rb") as file:
                        client_public = file.read()
                    # Generate Cyphering Block
                    client_pubkey = RSA.import_key(client_public)
                    cipher_rsa_en_client = PKCS1_OAEP.new(client_pubkey)

                    sym_key_encrypted = cipher_rsa_en_client.encrypt(sym_key)
                    connectionSocket.send(sym_key_encrypted)

                    # Print confirmation message
                    print(
                        f"Connection Accepted and Symmetric Key Generated for client: {username}"
                    )

                    # Receive OK message from client
                    okMsgEncrypted = connectionSocket.recv(2048)
                    okPadded = cipher_symmetric.decrypt(okMsgEncrypted)
                    okMsg = unpad(okPadded, 16)

                    # Start menu loop
                    menuChoice = "0"
                    while menuChoice != "4":
                        # Send client menu message
                        menuMsg = (
                            "Select the operation:\n1) Create and send an email\n2) Display the inbox\n"
                            "3) Display the email contents\n4) Terminate the connection\nchoice: "
                        )
                        menuMsgEncrypted = cipher_symmetric.encrypt(
                            pad(menuMsg.encode("ascii"), 16)
                        )
                        connectionSocket.send(menuMsgEncrypted)

                        # Receive menu choice from client
                        menuChoiceEncrypted = connectionSocket.recv(2048)
                        menuChoicePadded = cipher_symmetric.decrypt(menuChoiceEncrypted)
                        menuChoice = unpad(menuChoicePadded, 16).decode("ascii")

                if validUser == 0:
                    # Invalid user, send termination notice
                    invalidMsg = "Invalid username or password"
                    connectionSocket.send(invalidMsg.encode("ascii"))
                    print(
                        f"The received client information: {username} is invalid (Connection Terminated)."
                    )

                connectionSocket.close()

                return

            # Parent doesn't need this connection
            connectionSocket.close()

        except socket.error as e:
            print("An error occured:", e)
            serverSocket.close()
            sys.exit(1)
        except:
            print("Goodbye")
            serverSocket.close()
            sys.exit(0)


# -------
server()
