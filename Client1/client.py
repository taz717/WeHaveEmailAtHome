import socket
import os, datetime
import sys
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def delay(seconds):
    start_time = datetime.datetime.now()
    while True:
        current_time = datetime.datetime.now()
        elapsed_time = (current_time - start_time).total_seconds()
        if elapsed_time >= seconds:
            break

def client():
    # Server Information
    serverName = input("Enter the server IP or name: ")
    serverPort = 13000

    # Open server public key from file
    with open('server_public.pem', 'rb') as file:
        server_public = file.read()
    # Generate Cyphering Block
    server_pubkey = RSA.import_key(server_public)
    cipher_rsa_en = PKCS1_OAEP.new(server_pubkey)

    # Open server private key from file
    with open('server_private.pem', 'rb') as file:
        server_private = file.read()
    # Generate decrypting block
    server_privkey = RSA.import_key(server_private)
    cipher_rsa_dec_server = PKCS1_OAEP.new(server_privkey)

    # Open client private key from file
    with open('client1_private.pem', 'rb') as file:
        client_private = file.read()
    # Generate decrypting block
    client_privkey = RSA.import_key(client_private)
    cipher_rsa_dec = PKCS1_OAEP.new(client_privkey)

    # Create client socket that useing IPv4 and TCP protocols
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:', e)
        sys.exit(1)

    try:
        # Client connect with the server
        clientSocket.connect((serverName, serverPort))

        # Client gets user info
        username = input("Enter your username: ")
        password = input("Enter your password: ")

        # Client sends user info
        userEncrypted = cipher_rsa_en.encrypt(username.encode('ascii'))
        delay(0.1)
        clientSocket.send(userEncrypted)

        passEncrypted = cipher_rsa_en.encrypt(password.encode('ascii'))
        delay(0.1)
        clientSocket.send(passEncrypted)

        # Client receives login response from server
        loginResponse = clientSocket.recv(2048)
        try:
            loginResponseString = loginResponse.decode('ascii')
        except:
            loginResponseString = "Valid user"

        if (loginResponseString == "Invalid username or password"):
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
        okMsgEncrypted = cipher_symmetric.encrypt(
            pad(okMsg.encode('ascii'), 16))
        clientSocket.send(okMsgEncrypted)

        # Start menu loop
        menuChoice = "0"
        while (menuChoice != "4"):
            # Receive menu message from server
            menuMsgEncrypted = clientSocket.recv(2048)
            menuMsgPadded = cipher_symmetric.decrypt(menuMsgEncrypted)
            menuMsg = unpad(menuMsgPadded, 16).decode('ascii')
            menuChoice = input(menuMsg)

            # Send menu choice to server
            menuChoiceEncrypted = cipher_symmetric.encrypt(
                pad(menuChoice.encode('ascii'), 16))
            clientSocket.send(menuChoiceEncrypted)

            if (menuChoice == "1"):
                # Sending Email Subprotocol
                # Receive send email message from server
                sendEmailMsgEncrypted = clientSocket.recv(2048)
                sendEmailMsgPadded = cipher_symmetric.decrypt(
                    sendEmailMsgEncrypted)
                sendEmailMsg = unpad(sendEmailMsgPadded, 16).decode('ascii')

                # Check for attacker interference
                if (sendEmailMsg != "Send the email"):
                    print("Malicious user sending messages")

                # Get email specifications from client
                destinations = input("Enter destinations (separated by ;): ")
                title = input("Enter title: ")
                loadCheck = input(
                    "Would you like to load contents from a file? (Y/N): ")

                # Error check user response
                while (loadCheck not in "YyNn"):
                    loadCheck = input(
                        'Invalid response, please enter "Y" for yes or "N" for no')

                if (loadCheck.upper() == "Y"):
                    # User is loading email content from a text file
                    print("lit")

                else:
                    # User is entering contents manually
                    content = input("Enter message contents: ")

                # Calculate the length of the email contents
                contentLength = len(content)

                # Compose the email components
                fromStr = f"From: {username}\n"

                toStr = f"To: {destinations}\n"

                titleStr = f"Title: {title}\n"

                lengthStr = f"Content Length: {str(contentLength)}\n"

                contentStr = f"Content:\n{content}"

                # Append components to single string for email
                email = fromStr + toStr + titleStr + lengthStr + contentStr

                # Encrypt email to prepare it for sending
                emailEncrypted = cipher_symmetric.encrypt(
                    pad(email.encode('ascii'), 16))

                # Sending email to server
                # Find size of email string
                emailSize = sys.getsizeof(emailEncrypted)

                print(f"emailSize: {emailSize}")
                emailSize = str(emailSize)

                # Send size of email to server
                emailSizeEncrypted = cipher_symmetric.encrypt(
                    pad(emailSize.encode('ascii'), 16))
                clientSocket.send(emailSizeEncrypted)

                # Send email
                clientSocket.sendall(emailEncrypted)

                # Print send confirmation to client
                print("The message is sent to the server.")

        # Client terminate connection with the server
        clientSocket.close()

    except socket.error as e:
        print('An error occured:', e)
        clientSocket.close()
        sys.exit(1)


# ----------
client()
