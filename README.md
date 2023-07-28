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

### Assumptions made
- The server is run on a machine with a static IP address
- The server is run on a machine that is not accessible by anyone else
- No new accounts will be created after the server is started
- The server will not be restarted while clients are connected, connecting
    sendings email or disconnecting
- The only way to add a new account is by adding their information to the JSON
    file while the server is not online
- Each client only has one device that they will use to connect to the server

### Status
The project is complete and working. The server and client can be run on
different machines. The server can handle multiple clients at the same time.
There is always more room for error checking however, with the time constraints
on the project, there was an adequate amount of error checking implemented.

## Testing
### Attempted tests
#### Server Tests
- Test that the server can handle multiple clients
- Test that the server can handle multiple clients sending emails at the same
    time
- Test that the server can handle multiple clients sending emails to the same
    client at the same time
- Test that the server can handle multiple clients sending emails to multiple
    clients at the same time
- Test that the server can handle a client sending an email to a client that
    does not exist

#### Client Tests
- Test that the client can handle a server that does not exist
- Test that the client can handle a server that does not exist at the same time
    as another client sending an email to a client that does exist
- Test that the client can handle a server that does not exist at the same time
    as another client sending an email to a client that does not exist



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
- The server does not use a firewall to prevent the client from overloading the
    server with requests. This means that the client can prevent other clients
    from sending emails.
- The server does not prevent a client from logging on multiple times with the
    same username. This means that they can prevent other clients from logging
    in by using up all the available connections.

### Potential hacks
- The server could be hacked to read the emails stored on the server.
- The server could be hacked to read the public keys stored on the server.
- The client could be hacked to read the private keys stored on the client.
- Assuming the client is the attacker, the client could overload the server with
    requests to prevent other clients from sending emails.
- Assuming the client is the attacker, the client could log on multiple times
    with the same username to prevent other clients from logging in.

### How to improve security
- The server could use encryption to store the emails on the server. This would
    prevent anyone with access to the server from reading the emails.
- The server could use encryption to store the public keys on the server. This
    would prevent anyone with access to the server from reading the public keys.
- The client could use encryption to store the private keys on the client. This
    would prevent anyone with access to the client from reading the private keys.
- The server could use a firewall to prevent the client from overloading the
    server with requests.
- The server could prevent a client from logging on multiple times with the same
    username by adding a list of currently logged in users and checking it before
    allowing a client to log in.

## Section V - Attack Choice
### What is the attack?
DDOS attack on the server by logging on multiple times with the same username.

### Why did we choose it?
This attack had the most potential to cause problems for other clients as 
it could be made by the client without the client even knowing what they are doing.
If client1 for example attempted to login on multiple devices at the same time not
knowing that there was a limit of five users at a time, they could prevent other
clients from logging in.

### Solution
The solution to this attack is to add a list of currently logged in users and
checking it before allowing a client to log in. This would prevent a client from
logging on multiple times with the same username.

This solution is not the best solution as it restricts the client from being
able to login on multiple devices at the same time. However, there was an assumption
made earlier in the process of analyzing security risks in the project that 
states that each client only has one device that they will use to connect to the
server.

### How to implement
- Add a list of currently logged in users to the server
- Check the list before allowing a client to log in
- If the client is already logged in, do not allow them to log in again

## General
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
