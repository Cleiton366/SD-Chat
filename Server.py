import socket
import threading

HEADER = 64
PORT = 3000
SERVER = socket.gethostbyname(socket.gethostname())
ADDRESS = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!Disconnect"
CLIENTS = []

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDRESS)


def handle_client(connection, address):
    print(f"[NEW CONNECTION] {address} connected.")
    CLIENTS.append(connection)

    connected = True
    while connected:
        msg = connection.recv(HEADER).decode(FORMAT)
        user_name = connection.recv(HEADER).decode(FORMAT)
        if msg == DISCONNECT_MESSAGE:
            CLIENTS.remove(connection)
            connected = False
            break
        send_message(connection, msg, user_name)

    connection.close()

def send_message(sender_client, message, sender_user_name):
    msg = sender_user_name + ": "+ message
    data = msg.encode(FORMAT)
    for client in CLIENTS:
        if(client != sender_client):
            client.send(data)
        

def start():
    server.listen()
    print(f"[LISTENING] Server is listening on {SERVER}")
    while True:
        connection, address = server.accept()
        thread = threading.Thread(target=handle_client, args=(connection, address))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")


print("[STARTING] server is starting...")
start()