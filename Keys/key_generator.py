from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP


def pairKeygen():
    """
    Function to generate a pair of private and public keys. Takes no parameters and returns
    a private and a public key in that order.

    Ex. usage
    privateKey1, publicKey1 = pairKeygen()
    """
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    return private_key, public_key


if __name__ == "__main__":
    # Generate server private and public keys
    serverPrivKey, serverPubKey = pairKeygen()

    f = open("server_private.pem", "wb")
    f.write(serverPrivKey)
    f.close()

    f = open("server_public.pem", "wb")
    f.write(serverPubKey)
    f.close()

    storeKeys = []
    # Generate client keys for all 5 clients
    for i in range(1, 6):
        tempPriv, tempPub = pairKeygen()
        storeKeys.append(tempPriv)
        storeKeys.append(tempPub)

    # Assign client 1 private and public keys
    client1PrivKey = storeKeys[0]
    client1PubKey = storeKeys[1]

    # Assign client 2 private and public keys
    client2PrivKey = storeKeys[2]
    client2PubKey = storeKeys[3]

    # Assign client 3 private and public keys
    client3PrivKey = storeKeys[4]
    client3PubKey = storeKeys[5]

    # Assign client 4 private and public keys
    client4PrivKey = storeKeys[6]
    client4PubKey = storeKeys[7]

    # Assign client 5 private and public keys
    client5PrivKey = storeKeys[8]
    client5PubKey = storeKeys[9]

    # Create key files for client 1
    f = open("client1_private.pem", "wb")
    f.write(storeKeys[0])
    f.close()

    f = open("client1_public.pem", "wb")
    f.write(storeKeys[1])
    f.close()

    # Create key files for client 2
    f = open("client2_private.pem", "wb")
    f.write(storeKeys[2])
    f.close()

    f = open("client2_public.pem", "wb")
    f.write(storeKeys[3])
    f.close()

    # Create key files for client 3
    f = open("client3_private.pem", "wb")
    f.write(storeKeys[4])
    f.close()

    f = open("client3_public.pem", "wb")
    f.write(storeKeys[5])
    f.close()

    # Create key files for client 4
    f = open("client4_private.pem", "wb")
    f.write(storeKeys[6])
    f.close()

    f = open("client4_public.pem", "wb")
    f.write(storeKeys[7])
    f.close()

    # Create key files for client 5
    f = open("client5_private.pem", "wb")
    f.write(storeKeys[8])
    f.close()

    f = open("client5_public.pem", "wb")
    f.write(storeKeys[9])
    f.close()

    print("finished")
