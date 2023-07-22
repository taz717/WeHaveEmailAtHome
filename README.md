# CMPT361_Final
## Taz Khallaf, Travis Mundy and Adam Polywkan

### What is it?
This is a simple mailbox program that uses a server to relay emails between
clients. The project is written in python and uses the Crypto library for
encryption.

### How does it work?
The server is run on a machine with a static IP address. Clients connect to the
server and send emails to each other through the server. The server stores
the emails in client directories located in the server directory. The server
also stores the public keys of each client in the server directory. The server
uses the public keys to encrypt emails before sending them to the client.

### What is the purpose?
The purpose of this project is to demonstrate the use of encryption in a
client-server application. The encryption is used to protect the privacy of
the emails sent between clients.

## Security
### How is it secure?
The server uses the public keys of the clients to encrypt the emails before
sending them to the client. The client uses their private key to decrypt the
email. This ensures that only the client can read the email. The server also
uses the public keys to verify the identity of the client. This ensures that
the client is who they say they are.

### How is it not secure?
- The server does not use any encryption to store the emails on the server. This
    means that anyone with access to the server can read the emails.
- The serveralso does not use any encryption to store the public keys on the server.
    This means that anyone with access to the server can read the public keys.
- The server also does not use any encryption to store the private keys on the
    client. This means that anyone with access to the client can read the private
    keys.

### Potential hacks
- The server could be hacked to read the emails stored on the server.
- The server could be hacked to read the public keys stored on the server.
- The client could be hacked to read the private keys stored on the client.
- Assuming the client is the attacker, the client could overload the server with
    requests to prevent other clients from sending emails.

### How to improve security
- The server could use encryption to store the emails on the server. This would
    prevent anyone with access to the server from reading the emails.
- The server could use encryption to store the public keys on the server. This
    would prevent anyone with access to the server from reading the public keys.
- The client could use encryption to store the private keys on the client. This
    would prevent anyone with access to the client from reading the private keys.
- The server could use a firewall to prevent the client from overloading the
    server with requests.


### How to use?
- make sure you have python installed
- install the Crypto library
- run the key generation script if a new key is needed
- run the server script
- run the client script
- follow instructions on client script

### Resources and Credits
#### Libraries used (outside of python standard library)
- Crypto

#### Debugging aid
These are just links used to help debug the program (stack overflow, etc)

### Python naming convetions used
https://peps.python.org/pep-0008/

#### TLDR
- classes use CapWords
- functions use snake_case
- methods use snake_case
- constants use SNAKE_CAP_WORDS
- vars use camelCase

The one exception to this rule is the special vars used for keys to match
assignment specs.
