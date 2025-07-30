import asyncio
import os
import time
import base64
import hmac
import hashlib
import traceback
from message import Message

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey 
from cryptography.hazmat.primitives import serialization, hashes


host = '127.0.0.1'
port = 4444

client_list = []
rooms = []

MAIN_MENU_CODE = '#00000000'

class Client:
    def __init__(self, ipaddress, username, reader : asyncio.StreamReader, writer: asyncio.StreamWriter, aes_key):
        self.ipaddress = ipaddress
        self.username = username
        self.reader = reader
        self.writer = writer
        self.aes_key = aes_key
        self.owned_rooms_count = 0
        self.current_room = rooms[0] #main_menu 
        rooms[0].add_member(self)
    async def send_secure_message(self, message):
        secure_msg = construct_secure_message(self.aes_key, message)
        self.writer.write((secure_msg.to_json() + "\n").encode())
        await self.writer.drain()
    async def receive_secure_message(self):
        message = await receive_secure_message_and_log(self.reader, self.writer, self.aes_key)
        message = message.strip()
        return message
    def switch_room(self, room):
        assert self.current_room
        assert self in self.current_room.members
        if room == self.current_room:
            return
        self.current_room.members.remove(self)
        self.current_room = room
        room.add_member(self)
    async def join(self, room: 'Room'):
        if room.has_banned_user_with_username(self.username):
            message = f"Server : You are banned from {room.code}. Unless the owner unbans you, you can't join."
            await self.send_secure_message(message)
            return
        if room.has_password():
            message = f"Server: Enter password for this room ({room.code}): "
            await self.send_secure_message(message)
            received_password = await self.receive_secure_message()
            if room.is_correct_password(received_password):
                self.switch_room(room)
                message = f"Server: You have successfully entered the room {room.code}."
                await self.send_secure_message(message)
            else:
                message = "Server: Wrong password."
                await self.send_secure_message(message)
        else:
            if not self.current_room and room.code == MAIN_MENU_CODE: #for initial connection when entering menu
                self.current_room = room
                room.add_member(self)
            else:
                self.switch_room(room)
            message = f"Server: You have successfully entered the room {room.code}."
            await self.send_secure_message(message)
    async def create_room(self, room_code:str):
        for room in rooms:
            assert(room.code != room_code)
        r = Room(self.username, room_code)
        self.owned_rooms_count += 1
        message = f"Server: Room {room_code} has been created and is now owned by you."
        await self.send_secure_message(message)
        await self.join(r)
    async def prompt_and_get_response(self, message):
        await self.send_secure_message(message)
        received = await self.receive_secure_message()
        return received



class Room:
    def __init__(self, owner_name:str, code):
        self.owner_name = owner_name 
        self.code = code
        self.password = None
        self.members = []
        self.banned_members = []
    async def set_password(self, attempter:Client):
        if attempter.username != self.owner_name:
            message = "Server: You don't have the authority to do that in this room."
            await attempter.send_secure_message(message)
            return
        if self.has_password():
            message = "Server: Enter current password"
            received_password_old = await attempter.prompt_and_get_response(message)
            if self.password != received_password_old:
                message = "Server: Wrong password. To try again, run the command again."
                await attempter.send_secure_message(message)
                return
            message = "Server: Enter new password"
            received_password_new = await attempter.prompt_and_get_response(message)
            if self.password == received_password_old:
                message = "Server: New password cannot be the same as old password."
                await attempter.send_secure_message(message)
                return
            self.password = received_password_new
            message = "Server: Password change successful"
            await attempter.send_secure_message(message)
        else:
            message = "Server: Enter new password"
            received_password = await attempter.prompt_and_get_response(message)
            self.password = received_password
            message = "Server: Password was set successfully"
            await attempter.send_secure_message(message)
    def has_password(self):
        return self.password is not None
    def is_correct_password(self, password):
        return password == self.password
    def add_member(self, client:Client):
        self.members.append(client)
    async def ban(self, to_be_banned_username:str):
        self.banned_members.append(to_be_banned_username)
        for cl in self.members:
            if cl.username == to_be_banned_username:
                message = f"Server: You have banned from room {self.code} by {self.owner_name}."
                await cl.send_secure_message(message)
                await exit_room(cl)
            else:
                await cl.send_secure_message(f"Server: {to_be_banned_username} has been banned from this room({self.code}).")
    def has_banned_user_with_username(self, username:str):
        return username in self.banned_members

async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    print(f"Connection from {addr}")
    new_client = None
    try:
        aes_key = await establish_secure_channel_and_get_aes_key(reader, writer)

        print("Secure channel established.")

        username = await start_authentication_sequence(reader, writer, aes_key)

        new_client = Client(addr, username, reader, writer, aes_key)
        client_list.append(new_client)

        await new_client.join(rooms[0])

        await receive_loop(new_client)

    except BaseException as e:
        print(f"[handle_client] : {e}")
        traceback.print_exc()
    finally:
        print("final block")
        if new_client:
            if new_client in client_list:
                client_list.remove(new_client)
        writer.close()
        await writer.wait_closed()


async def start_authentication_sequence(reader, writer, aes_key):

    print("Starting authentication sequence.")

    msg = "Server: Enter username"
    secure_msg = construct_secure_message(aes_key, msg)
    writer.write((secure_msg.to_json() + "\n").encode())
    await writer.drain()

    username = await receive_secure_message_and_log(reader, writer, aes_key)
    username = username.strip()

    msg = "Server: Enter password"
    secure_msg = construct_secure_message(aes_key, msg)
    writer.write((secure_msg.to_json() + "\n").encode())
    await writer.drain()

    password = await receive_secure_message_and_log(reader, writer, aes_key)
    password = password.strip()
    count = 1
    while not (username == "usertest" and password == "password"):
        msg = "Server: Wrong Credentials, try again.\nServer: Enter username"
        secure_msg = construct_secure_message(aes_key, msg)
        writer.write((secure_msg.to_json() + "\n").encode())
        await writer.drain()

        username = await receive_secure_message_and_log(reader, writer, aes_key)
        username = username.strip()
        
        msg = "Server : Enter your password"
        secure_msg = construct_secure_message(aes_key, msg)
        writer.write((secure_msg.to_json() + "\n").encode())
        await writer.drain()

        password = await receive_secure_message_and_log(reader, writer, aes_key)
        password = password.strip()
        count += 1
        if count == 3:
            raise Exception("Too many wrong attempts")
    

    msg = "Server: Login successful."
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

    if not isinstance(public_key, RSAPublicKey):
        raise TypeError("Only RSA public keys are supported for encryption.")

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

async def receive_loop(client:Client):
    while True:
        message = await client.receive_secure_message()
        print(f"\n[Received] {message}")
        if message.startswith('/'):
            await handle_command(client,message)
        else:
            message = f"{client.username}: {message}"
            if not client.current_room.code == MAIN_MENU_CODE:
                for cl in client.current_room.members:
                    await cl.send_secure_message(message)
            else:
                message = "Server: You can't message in the main menu, type /help for help"
                await client.send_secure_message(message)

async def handle_command(client: Client, message: str):
    parts = message[1:].strip().split()
    if not parts:
        await client.send_secure_message("Server: Invalid command. /help for help")
        return

    cmd = parts[0].lower()
    args = parts[1:]
    if cmd not in commands:
        await client.send_secure_message("Server: Invalid command. /help for help")
        return
    func, min_arg_count = commands[cmd]
    if len(args) < min_arg_count:
        await client.send_secure_message("Server: Invalid use of the command. /help for help")
        return
    await func(client, *args[:min_arg_count])


#Commands start here

async def list_rooms(client:Client):
    message = ""
    for room in rooms:
        message += f"{room.code}\n"
    await client.send_secure_message(message)

async def send_help_message(client:Client):
    message = """Server: \"To list the rooms already present use \'/list\' command.
    To join a room, use \'/join\'  e.g. \'/join #12345678\', (if the room has a password, you will have to provide one).
    If you wish to create a room, join a non-existing room and after entering use \'/setpasswd\' command to put a password to it if you wish.
    To exit the room you are in and return to main menu, use the \'/exitroom\' command.
    To receive this help message use the \'/help\' command.\""""
    await client.send_secure_message(message)

async def exit_room(client:Client):
    await client.join(rooms[0])
    message = "Server: You are in the main menu now."
    await client.send_secure_message(message)

MAX_ROOMS_PER_CLIENT = 3
async def join_room(client:Client, room_code):
    if not room_code.startswith('#') or len(room_code) != 9 or not room_code[1:].isalnum():
        await client.send_secure_message("Server: Room code must be in format '#12345678' and alphanumeric.")
        return

    for room in rooms:
        if room_code == room.code:
            await client.join(room)
            return
    if client.owned_rooms_count < MAX_ROOMS_PER_CLIENT:
        await client.create_room(room_code)
    else:
        message = f"Server: You already own {MAX_ROOMS_PER_CLIENT} rooms, you can't create more."
        await client.send_secure_message(message)

async def set_room_password(client:Client):
    if client.current_room.code == MAIN_MENU_CODE:
        message = "Server: You can't do that in the main menu."
        await client.send_secure_message(message)
    else:
        r = client.current_room
        await r.set_password(client)

async def kick_all(client:Client):
    r = client.current_room
    if r.owner_name != client.username:
        message = f"Server: You can't do that in the current room."
        await client.send_secure_message(message)
        return

    for cl in client.current_room.members:
        if cl != client:
            await kick(client, cl.username)

async def kick(client:Client, to_be_kicked:str):
    r = client.current_room
    if r.owner_name != client.username:
        message = f"Server: You can't do that in the current room."
        await client.send_secure_message(message)
        return
    if to_be_kicked == client.username:
        message = f"Server: You can't kick yourself. You can use the \'/exitroom\' command to exit the room."
        await client.send_secure_message(message)
        return
    for cl in r.members:
        if cl.username == to_be_kicked:
            message = f"Server: You have been kicked by {client.username}"
            await exit_room(cl)
            await cl.send_secure_message(message)

async def ban(client:Client, to_ban_username:str):
    r = client.current_room
    if r.owner_name != client.username:
        message = f"Server: You can't do that in the current room."
        await client.send_secure_message(message)
        return
    if client.username == to_ban_username:
        message = f"Server: You can't ban yourself"
        await client.send_secure_message(message)
        return
    await r.ban(to_ban_username)

commands = {
    #f"{command_name}:(func_name, num_of_args)
    "list":(list_rooms, 0),
    "help":(send_help_message, 0),
    "join":(join_room, 1),
    "setpasswd":(set_room_password, 0),
    "exitroom":(exit_room, 0),
    "kickall":(kick_all, 0),
    "kick":(kick, 1),
    "ban":(ban, 1)
}

#Commands end here

async def receive_secure_message_and_log(reader: asyncio.StreamReader, writer : asyncio.StreamWriter, aes_key: bytes, max_delay_sec=5) -> str:
    data = await reader.readline()
    if not data:
        raise ConnectionError("Connection closed by peer.")

    msg = Message.from_json(data.decode())

    nonce = base64.b64decode(msg.nonce)

    log_nonce(nonce, writer)

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

def log_nonce(nonce: bytes, writer: asyncio.StreamWriter): #maybe make this in memory
    try:
        with open("nonces.txt", "r") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        lines = []
    
    nonce_hex = nonce.hex()

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
            if prev_nonce == nonce_hex:
                raise ValueError(f"Replay attack detected from {writer.get_extra_info('peername')} with nonce: {nonce}")

    new_lines.append(f"{nonce_hex} {current_time}")

    with open("nonces.txt", "w") as f:
        for line in new_lines:
            f.write(f"{line}\n")



async def main():
    main_menu = Room("", MAIN_MENU_CODE)
    rooms.append(main_menu)

    server = await asyncio.start_server(handle_client, host, port)
    print(f"Server listening on {host}:{port}")
    async with server:
        await server.serve_forever()

asyncio.run(main())
