import socket
import time
import threading
import ssl
import datetime
import json
import jwt
import uuid
import random
from dotenv import dotenv_values
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

HEADER = 64
PORT = 3000
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!Disconnect"
SERVER = socket.gethostbyname(socket.gethostname())
ADDRESS = (SERVER, PORT)
USER_NAME = ""
config = dotenv_values(".env")
SECRET_KEY = config['SECRET_KEY']

MESSAGE_SENT = "Message successfully sent"
last_message_sent = True
message_sent_time = time.time()
last_message = ""

def generate_token(username):
    payload = {"username": username}
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token

def generate_self_signed_cert():
    # Generate a new private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Create a self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"BR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Ceará"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Quixadá"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UFC"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(private_key, hashes.SHA256(), default_backend())

    # Save private key to a file
    private_key_filename = "private.key"  # Specify the desired shorter filename
    with open(private_key_filename, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save certificate to a file
    cert_filename = "certificate.crt"  # Specify the desired shorter filename
    with open(cert_filename, "wb") as f:
        f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))

    return private_key_filename, cert_filename

def send(client, msg):
    global last_message
    global last_message_sent
    message_sent_time = time.time()
    last_message = msg
    try:
        if random.randint(0,9) > 4:
            raise socket.error("Forçando um erro")
        request = {
            "origin": "client",
            "message": msg,
            "user_name": USER_NAME
        }
        request = json.dumps(request)
        client.send(request.encode())
    except socket.error as e:
        print(f"A error as ocurred! Error: {e}")
        last_message_sent = False
    except socket.timeout as e:
        print(f"A timeout error as ocurred! Error: {e}")
        last_message_sent = False

def handle_messages(client_socket):
    global last_message_sent
    threading.Thread(target=check_unconfirmed_messages, args=(client_socket,)).start()
    while True:
        try:
            response = client_socket.recv(1024).decode(FORMAT)
            try:
                response = json.loads(response)
                message = response["message"]
                if show_prints_request_response:
                    print(response)
                if not message:
                    break
                if message == MESSAGE_SENT or message == "Nobody is online at the moment":
                    last_message_sent = True
                if response["origin"] == "client":    
                    user_name = response["user_name"]
                    print(f"{user_name}: {message}")
                if response["origin"] == "server":
                    print(f"Server: {message}")
                    if message == "Connection closed":
                        last_message_sent = True
                        return
                
            except:
                pass
        except Exception as e:
            print("Error:", str(e))
            break

def handle_auth(client):
    print("Trying to authenticate...")
    token = generate_token(USER_NAME)
    auth_message = {
        "action": "authenticate",
        "token": token.encode()
    }
    
    # Convert bytes values in the auth_message dictionary to strings
    auth_message_str = {k: v.decode() if isinstance(v, bytes) else v for k, v in auth_message.items()}

    # Serialize the updated dictionary to JSON
    auth_message_json = json.dumps(auth_message_str)

    # Encode as bytes before sending
    client.send(auth_message_json.encode())

def check_unconfirmed_messages(client):
    global last_message_sent
    global last_message
    while True:
        if time.time() - message_sent_time > 5:
            if not last_message_sent:
                print("Trying again.")
                request = {
                    "origin": "client",
                    "message": last_message,
                    "user_name": USER_NAME
                }
                request = json.dumps(request)
                client.send(request.encode())
                if last_message == DISCONNECT_MESSAGE:
                    break
        time.sleep(0.1)

def start():
    global last_message_sent
    #GENERATING self-sign certificates for encrypted connection
    private_key, cert = generate_self_signed_cert()
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(certfile=cert, keyfile=private_key)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client = context.wrap_socket(client, server_hostname=ADDRESS[0])
    client.connect(ADDRESS)

    handle_auth(client)

    thread = threading.Thread(target=handle_messages, args=(client,))
    thread.start()

    connected = True
    while connected:
        if last_message_sent:
            newMsg = input()
            send(client, newMsg)
            if(newMsg == DISCONNECT_MESSAGE):
                last_message_sent = False
                connected = False
                break

USER_NAME = username = input("Before chatting, enter your username: ")
print("Name Saved, good chatting :)")

show_prints_request_response = False
forcar_erros_mandar_mensagem = True

start()