import socket
import time
import threading
import ssl
import datetime
import json
import jwt
from dotenv import dotenv_values
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

HEADER = 64
PORT = 3000
SERVER = socket.gethostbyname(socket.gethostname())
ADDRESS = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!Disconnect"
CLIENTS = []
config = dotenv_values(".env")
SECRET_KEY = config['SECRET_KEY']

MESSAGE_SENT = "Message successfully sent"
messages_not_sent = []

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

def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload["username"]
    except jwt.InvalidTokenError:
        return None

def handle_auth(client):
    auth_data = client.recv(1024).decode()
    auth_message = json.loads(auth_data)

    token = auth_message.get("token")
    username = verify_token(token)

    if not username:
        print("Invalid token. Closing the connection.")
        client.close()
        return

def handle_client(connection, address):
    print(f"[NEW CONNECTION] {address} connected.")
    CLIENTS.append(connection)

    handle_auth(connection)
    connection.send("Server: Client authenticated".encode(FORMAT))

    connected = True
    while connected:
        msg = connection.recv(HEADER).decode(FORMAT)
        user_name = connection.recv(HEADER).decode(FORMAT)
        if msg == DISCONNECT_MESSAGE:
            connection.send(("Connection closed").encode(FORMAT))
            CLIENTS.remove(connection)
            connected = False
            break
        send_message(connection, msg, user_name)

    connection.close()

def check_unconfirmed_messages():
    global messages_not_sent
    while True:
        new_messages_not_sent = []
        for client, data, sender_client in messages_not_sent:
            try:
                client.send(data)
                sender_client.send(MESSAGE_SENT.encode(FORMAT))
            except:
                print("Oops! Something went wrong!")
                new_messages_not_sent.append((client, data, sender_client))
        messages_not_sent = new_messages_not_sent.copy()
        time.sleep(0.1)

def send_message(sender_client, message, sender_user_name):
    msg = sender_user_name + ": " + message
    data = msg.encode(FORMAT)
    for index,(client) in enumerate(CLIENTS):
        if client != sender_client:
            try:
                #raise socket.error("Forçando um erro")
                client.send(data)
                sender_client.send(MESSAGE_SENT.encode(FORMAT))
            except socket.error as e:
                messages_not_sent.append((client, data, sender_client))
    if index < 1:
        sender_client.send(MESSAGE_SENT.encode(FORMAT))
def start():
    print("[STARTING] server is starting...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDRESS)
    server.listen()
    print(f"[LISTENING] Server is listening on {SERVER}")

    #GENERATING self-sign certificates for encrypted connection
    private_key, cert = generate_self_signed_cert()
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=cert, keyfile=private_key)
    threading.Thread(target=check_unconfirmed_messages).start()
    while True:
            connection, address = server.accept()
            client_socket = context.wrap_socket(connection, server_side=True)
            thread = threading.Thread(target=handle_client, args=(client_socket, address))
            thread.start()
            print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 2}")

start()