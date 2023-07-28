# Description: This is the client program for the email system. It will
#              connect to the server and send and receive messages.
#              It will also generate a symmetric key and send it to the server
#              encrypted with the server's public key.
###############################################################################

import socket
import os, datetime
import sys
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

###############################################################################

def delay(seconds):
    """
    Delays the program for the specified number of seconds
    Params: seconds - the number of seconds to delay
    Return: None
    """
    start_time = datetime.datetime.now()
    while True:
        current_time = datetime.datetime.now()
        elapsed_time = (current_time - start_time).total_seconds()
        if elapsed_time >= seconds:
            break

###############################################################################

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

    # Find out which client is connected to generate keys
    directory = os.getcwd()
    folder = directory.split("/")
    clientName = folder[-1].lower()

    clientPubKeyName = clientName + "_public.pem"
    clientPrivKeyName = clientName + "_private.pem"

    # Open client public key from file
    with open(clientPubKeyName, 'rb') as file:
        client_public = file.read()
    # Generate Cyphering Block
    server_pubkey = RSA.import_key(server_public)
    cipher_rsa_en = PKCS1_OAEP.new(server_pubkey)

    # Open client private key from file
    with open(clientPrivKeyName, 'rb') as file:
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
        try:
            clientSocket.connect((serverName, serverPort))
        except:
            print("Invalid server name entered")
            clientSocket.close()
            sys.exit(1)

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
        delay(0.1)
        try:
            loginResponseString = loginResponse.decode('ascii')
        except:
            loginResponseString = "Valid user"

        if (loginResponseString == "Invalid username or password"):
            # Terminate the connection
            print("Invalid username or password.\nTerminating.")
            clientSocket.close()
            sys.exit(0)

        if (loginResponseString == "Entered username is already logged in"):
            # Terminate the connection
            print("Entered username is already logged in.\nTerminating.")
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
                    fileName = input("Enter filename: ")

                    # Error check valid file name in a loop
                    success = 0
                    while success == 0:
                        try:
                            f = open(fileName, "r")
                            content = f.read()
                            f.close()
                            success = 1
                        except:
                            fileName = input("No such file exists, please enter a valid file name: ")
                   
                else:
                    # User is entering contents manually
                    content = input("Enter message contents: ")

                    # Calculate the length of the email contents
                    contentLength = len(content)
                    
                    while contentLength > 1000000:
                        content = input("Max content length exceeded, please shorten your message")

                # REMOVE THIS IF CALCULATED WITH PRELOADED
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

                emailSize = str(emailSize)

                # Send size of email to server
                emailSizeEncrypted = cipher_symmetric.encrypt(
                    pad(emailSize.encode('ascii'), 16))
                clientSocket.send(emailSizeEncrypted)

                # Send email
                clientSocket.sendall(emailEncrypted)

                # Print send confirmation to client
                print("The message is sent to the server.")
            elif (menuChoice == "2"):
                inboxEncrypted = clientSocket.recv(2048)
                inboxPadded = cipher_symmetric.decrypt(inboxEncrypted)
                inboxMsg = unpad(inboxPadded, 16).decode('ascii')
                print(inboxMsg)

                 # Send OK response message to server
                okMsg = "OK"
                okMsgEncrypted = cipher_symmetric.encrypt(
                pad(okMsg.encode('ascii'), 16))
                clientSocket.send(okMsgEncrypted)

            elif (menuChoice == "3"):
                # Receive email index request from server
                emailIndexAskEncrypted = clientSocket.recv(2048)
                emailIndexAskPadded = cipher_symmetric.decrypt(emailIndexAskEncrypted)
                emailAskIndex = unpad(emailIndexAskPadded, 16).decode('ascii')

                index = input(emailAskIndex)

                # Send index to server
                indexEncrypted = cipher_symmetric.encrypt(
                    pad(index.encode('ascii'), 16))
                clientSocket.send(indexEncrypted)

                delay(0.1)

                # Receive email from server
                emailEncrypted = clientSocket.recv(2048)
                emailPadded = cipher_symmetric.decrypt(emailEncrypted)
                email = unpad(emailPadded, 16).decode('ascii')

                # Print email to client
                print(email)

                # Send OK response message to server
                okMsg = "OK"
                okMsgEncrypted = cipher_symmetric.encrypt(
                pad(okMsg.encode('ascii'), 16))
                clientSocket.send(okMsgEncrypted)

        # Client terminate connection with the server
        print(f"Terminating connection with server")
        clientSocket.close()

    except socket.error as e:
        print('An error occured:', e)
        clientSocket.close()
        sys.exit(1)


###############################################################################
if __name__ == "__main__":
    client()
