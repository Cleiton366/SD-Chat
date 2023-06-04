import socket
import threading

HEADER = 64
PORT = 3000
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!Disconnect"
SERVER = socket.gethostbyname(socket.gethostname())
ADDRESS = (SERVER, PORT)
USER_NAME = ""

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDRESS)

def send(msg):
    message = msg.encode(FORMAT)
    user_name = USER_NAME.encode(FORMAT)
    client.send(message)
    client.send(user_name)

def handle_messages():
    while True:
        data = client.recv(HEADER).decode(FORMAT)
        print(data)

def start():
    thread = threading.Thread(target=handle_messages)
    thread.start()

    connected = True
    while connected:
        newMsg = input()
        if(newMsg == DISCONNECT_MESSAGE):
            send(DISCONNECT_MESSAGE)
            connected = False
            client.close()
            break
        send(newMsg)

print("Before chatting, what is your name:")
user_name = input()
USER_NAME = user_name
print("Name Saved, good chatting :)")

start()