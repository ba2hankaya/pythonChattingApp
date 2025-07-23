import asyncio
import os
import time
import base64
import hmac
import hashlib
from message import Message

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


host = '127.0.0.1'
port = 4444

client_list = []
rooms = []

MAIN_MENU_CODE = '#00000000'

class Client:
    def __init__(self, ipaddress, username, reader : asyncio.StreamReader, writer: asyncio.StreamWriter, aes_key, roomcode = MAIN_MENU_CODE):
        self.ipaddress = ipaddress
        self.roomcode = roomcode
        self.username = username
        self.reader = reader
        self.writer = writer
        self.aes_key = aes_key
    async def send_secure_message(self, message):
        secure_msg = construct_secure_message(self.aes_key, message)
        self.writer.write((secure_msg.to_json() + "\n").encode())
        await self.writer.drain()
    async def receive_secure_message(self):
        message = await receive_secure_message_and_log(self.reader, self.writer, self.aes_key)
        message = message.strip()
        return message
    async def join(self, room: 'Room'):
        if room.has_password():
            message = "Enter password for this room: "
            await self.send_secure_message(message)
            received_password = await self.receive_secure_message()
            if room.try_password(received_password):
                self.roomcode = room.code
                message = "You have succesfully entered the room."
                await self.send_secure_message(message)
            else:
                message = "Wrong password."
                await self.send_secure_message(message)
        else:
            self.roomcode = room.code
            message = "You have succesfully entered the room."
            await self.send_secure_message(message)


class Room:
    def __init__(self, owner:Client, code):
        self.owner = owner 
        self.code = code
        self.password = None
    async def set_password(self, attemptor:Client):
        if attemptor == self.owner:
            if self.has_password():
                message = "Enter current password: "
                await attemptor.send_secure_message(message)
                received_password = await attemptor.receive_secure_message()
                if self.password == received_password:
                    message = "Enter new password: "
                    await attemptor.send_secure_message(message)
                    received_password = await attemptor.receive_secure_message()
                    self.password = received_password
                    message = "Password change successful"
                    await attemptor.send_secure_message(message)
                else:
                    message = "Wrong password. To try again, run the command again."
                    await attemptor.send_secure_message(message)
            else:
                message = "Enter new password: "
                await attemptor.send_secure_message(message)
                received_password = await attemptor.receive_secure_message()
                self.password = received_password
                message = "Password was set successfully"
                await attemptor.send_secure_message(message)
        else:
            message = "You don't have the authority to do that in this room."
            await attemptor.send_secure_message(message)
    def has_password(self):
        if not self.password:
            return False
        return True
    def try_password(self, password):
        return password == self.password


async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    print(f"Connection from {addr}")
    
    try:
        aes_key = await establish_secure_channel_and_get_aes_key(reader, writer)

        print("Secure channel established.")

        username = await start_authentication_sequence(reader, writer, aes_key)

        newclient = Client(addr, username, reader, writer, aes_key)
        client_list.append(newclient)

        await asyncio.gather(
            send_loop(newclient),
            receive_loop(newclient)
        )

        writer.close()
        await writer.wait_closed()
    except Exception as e:
        print(e)


async def start_authentication_sequence(reader, writer, aes_key):

    print("Starting authentication sequence.")

    msg = "Enter username: "
    secure_msg = construct_secure_message(aes_key, msg)
    writer.write((secure_msg.to_json() + "\n").encode())
    await writer.drain()

    username = await receive_secure_message(reader, writer, aes_key)
    username = username.strip()

    msg = "Enter password: "
    secure_msg = construct_secure_message(aes_key, msg)
    writer.write((secure_msg.to_json() + "\n").encode())
    await writer.drain()

    password = await receive_secure_message(reader, writer, aes_key)
    password = password.strip()
    count = 1
    while not (username == "usertest" and password == "password"):
        msg = "Wrong Credentials, try agian.\nEnter username: "
        secure_msg = construct_secure_message(aes_key, msg)
        writer.write((secure_msg.to_json() + "\n").encode())
        await writer.drain()

        username = await receive_secure_message(reader, writer, aes_key)
        username = username.strip()
        
        msg = "Enter password: "
        secure_msg = construct_secure_message(aes_key, msg)
        writer.write((secure_msg.to_json() + "\n").encode())
        await writer.drain()

        password = await receive_secure_message(reader, writer, aes_key)
        password = password.strip()
        count += 1
        if count == 3:
            raise Exception("Too many wrong attempts")
    

    msg = "Login successful."
    secure_msg = construct_secure_message(aes_key, msg)
    writer.write((secure_msg.to_json() + "\n").encode())
    await writer.drain()

    return username


async def establish_secure_channel_and_get_aes_key(reader, writer):

    data = await reader.readline()
    msg = Message.from_json(data.decode())

    if msg.type != "key_exchange":
        print("Unexpected message type.")
        writer.close()

    public_key_pem = msg.payload["rsa_public_key"]
    print(f"Received public key from client:\n{public_key_pem}")
    public_key = serialization.load_pem_public_key(public_key_pem.encode())

    aes_key = os.urandom(32)  # 256-bit AES key

    # Encrypt AES key with client's RSA public key
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_key_str = base64.b64encode(encrypted_aes_key).decode('utf-8')

    msg = Message(
        type="aes_key",
        payload={"encrypted_aes_key": encrypted_key_str}
    )

    json_str = msg.to_json() + '\n'
    writer.write(json_str.encode())
    await writer.drain()

    return aes_key


async def send_loop(client:Client):
    try:
        while True:
            msg = await asyncio.to_thread(input, "> ")
            await client.send_secure_message(msg)
    except (ConnectionError, asyncio.CancelledError):
        print("Send loop ended.")


async def receive_loop(client:Client, max_delay_sec=5):
    try:
        while True:
            message = await client.receive_secure_message()
            print(f"\n[Received] {message}")
    except (ConnectionError, asyncio.IncompleteReadError, asyncio.CancelledError):
        print("Receive loop ended.")

async def list_rooms(client:Client):
    message = ""
    for room in rooms:
        message += f"{room.code}\n"
    await client.send_secure_message(message)

async def send_help_message(client:Client):
    message = """To list the rooms already present use \'list\' command.\n
    To join a room, use \'join #{room_num}\', (if the room has a password, you will have to provide one).\n
    If you wish to create a room, join a non-existing room and after entering use setpasswd command to put a password to it if you wish.\n
    To exit the room you are in and return to main menu, use the \'exitroom\' command\n
    To receive this help message use the \'help\' command."""
    await client.send_secure_message(message)

async def exit_room(client:Client):
    client.roomcode = MAIN_MENU_CODE
    message = "You are in the main menu now."
    await client.send_secure_message(message)

async def join_room(client:Client, room_code):
    for room in rooms:
        if room_code == room.code:
            await client.join(room)
            return
    r = Room(client, room_code)
    rooms.append(r)
    message = f"You are the owner of the room {room_code}"
    await client.send_secure_message(message)

async def set_room_password(client:Client):
    if client.roomcode == MAIN_MENU_CODE:
        message = "You can't do that in the main menu."
        await client.send_secure_message(message)
    else:
        for room in rooms:
            if client.roomcode == room.code:
                r = room
                break
        await r.set_password(client)
        

commands = {
    "list":list_rooms,
    "help":send_help_message,
    "join":join_room,
    "setpasswd":set_room_password,
    "exitroom":exit_room
}

async def receive_secure_message_and_log(reader: asyncio.StreamReader, writer : asyncio.StreamWriter, aes_key: bytes, max_delay_sec=5) -> str:
    data = await reader.readline()
    if not data:
        raise ConnectionError("Connection closed by peer.")

    msg = Message.from_json(data.decode())

    nonce = base64.b64decode(msg.nonce)

    logNonce(nonce, writer)

    ciphertext = base64.b64decode(msg.payload["ciphertext"])
    tag = base64.b64decode(msg.payload["tag"])
    timestamp = msg.timestamp
    received_hmac = base64.b64decode(msg.hmac)

    current_time = int(time.time())
    if abs(current_time - timestamp) > max_delay_sec:
        raise ValueError("Message timestamp is too old or in the future.")

    data_to_auth = (
        base64.b64encode(nonce).decode() +
        base64.b64encode(ciphertext).decode() +
        base64.b64encode(tag).decode() +
        str(timestamp)
    ).encode()

    expected_hmac = hmac.new(aes_key, data_to_auth, hashlib.sha256).digest()

    if not hmac.compare_digest(received_hmac, expected_hmac):
        raise ValueError("HMAC authentication failed.")

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext.decode()


def construct_secure_message(aes_key: bytes, plaintext: str) -> Message:
    nonce = os.urandom(12)

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    tag = encryptor.tag

    timestamp = int(time.time())

    data_to_auth = (
        base64.b64encode(nonce).decode() +
        base64.b64encode(ciphertext).decode() +
        base64.b64encode(tag).decode() +
        str(timestamp)
    ).encode()

    hmac_digest = hmac.new(aes_key, data_to_auth, hashlib.sha256).digest()
    hmac_b64 = base64.b64encode(hmac_digest).decode()

    msg = Message(
        type="encrypted_msg",
        payload={
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "tag": base64.b64encode(tag).decode()
        },
        nonce=base64.b64encode(nonce).decode(),
        timestamp=timestamp,
        hmac=hmac_b64
    )

    return msg


NONCE_AWAIT_TIME = 30 # or whatever your nonce window is

def logNonce(nonce: str, writer: asyncio.StreamWriter): #maybe make this in memory
    try:
        with open("nonces.txt", "r") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        lines = []

    new_lines = []
    current_time = int(time.time())

    for line in lines:
        try:
            prev_nonce, timestamp = line.split(" ")
            timestamp = int(timestamp)
        except ValueError:
            continue  # skip malformed lines

        if current_time - timestamp < NONCE_AWAIT_TIME:
            new_lines.append(f"{prev_nonce} {timestamp}")
            if prev_nonce == nonce:
                raise ValueError(f"Replay attack detected from {writer.get_extra_info('peername')} with nonce: {nonce}")

    new_lines.append(f"{nonce} {current_time}")

    with open("nonces.txt", "w") as f:
        for line in new_lines:
            f.write(f"{line}\n")



async def main():
    server = await asyncio.start_server(handle_client, host, port)
    print(f"Server listening on {host}:{port}")
    async with server:
        await server.serve_forever()

asyncio.run(main())
