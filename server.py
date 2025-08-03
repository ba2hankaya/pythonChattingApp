import asyncio
import os
import time
import base64
import hmac
import hashlib
import traceback
import weakref
import gc
from message import Message

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey 
from cryptography.hazmat.primitives import serialization, hashes

import logging

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

fileHandler = logging.FileHandler('server.log')
fileHandler.setLevel(logging.INFO)

fileHandler2 = logging.FileHandler('server.debug.log')
fileHandler2.setLevel(logging.DEBUG)

consoleHandler = logging.StreamHandler()
consoleHandler.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s\t%(levelname)s\t%(message)s')

fileHandler.setFormatter(formatter)
fileHandler2.setFormatter(formatter)
consoleHandler.setFormatter(formatter)

logger.addHandler(fileHandler)
logger.addHandler(fileHandler2)
logger.addHandler(consoleHandler)


HOST_IP = '127.0.0.1'
HOST_PORT = 4444
client_list = []
client_list_lock = asyncio.Lock()
rooms = []
rooms_lock = asyncio.Lock()

nonce_dict = {}
nonce_lock = asyncio.Lock()

MAIN_MENU_CODE = '#00000000'


class Client:
    def __init__(self, ipaddress, username, reader : asyncio.StreamReader, writer: asyncio.StreamWriter, aes_key):
        self.ipaddress = ipaddress
        self.username = username
        self.reader = reader
        self.writer = writer
        self.aes_key = aes_key
        self.owned_rooms_count = 0
    async def async_init(self):
        async with rooms_lock:
            self.current_room = rooms[0] #rooms[0] is main menu
            await rooms[0].add_member(self)
    async def send_secure_message(self, message):
        secure_msg = construct_secure_message(self.aes_key, message)
        self.writer.write((secure_msg.to_json() + "\n").encode())
        await self.writer.drain()
        logger.debug(f"Sent client '{self.username}' with IP address '{self.ipaddress}' message: '{message}'")
    async def receive_secure_message(self):
        message = await receive_secure_message_and_log(self.reader, self.writer, self.aes_key)
        message = message.strip()
        return message
    async def switch_room(self, target_room):
        assert self.current_room
        assert await self.current_room.client_is_in_room(self)
        if target_room == self.current_room:
            return
        await self.current_room.remove_member(self)
        self.current_room = target_room
        await target_room.add_member(self)
    async def join(self, room: 'Room'):
        if await room.has_banned_user_with_username(self.username):
            message = f"Server : You are banned from {room.code}. Unless the owner unbans you, you can't join."
            await self.send_secure_message(message)
            return
        if await room.has_password():
            message = f"Server: Enter password for this room ({room.code}): "
            await self.send_secure_message(message)
            received_password = await self.receive_secure_message()
            if await room.is_correct_password(received_password):
                await self.switch_room(room)
                message = f"Server: You have successfully entered the room {room.code}."
                await self.send_secure_message(message)
                message = f"Server: User '{self.username}' has joined the room."
                await room.broadcast_message(message)
            else:
                message = "Server: Wrong password."
                await self.send_secure_message(message)
        else:
            await self.switch_room(room)
            message = f"Server: You have successfully entered the room {room.code}."
            await self.send_secure_message(message)
            message = f"Server: User '{self.username}' has joined the room."
            await room.broadcast_message(message)
    async def create_room(self, room_code:str):
        async with rooms_lock:
            for room in rooms:
                if(room.code == room_code):
                    logger.error(f"Already existing room was tried to be created, shouldn't be possible. Client that made the request is: '{self.username}' with IP address: '{self.ipaddress}'")
                    raise Exception("Bad Room Create")
            r = Room(self.username, room_code)
            rooms.append(r)
            logger.debug(f"New room was created with code '{room_code}' by client '{self.username}', owner is '{r.owner_name}'")
        self.owned_rooms_count += 1
        message = f"Server: Room {room_code} has been created and is now owned by you."
        await self.send_secure_message(message)
        await self.join(r)
    async def prompt_and_get_response(self, message):
        await self.send_secure_message(message)
        received = await self.receive_secure_message()
        logger.debug(f"Sent client '{self.username}' with IP Address '{self.ipaddress}' prompt: '{message}' and received back: '{received}'")
        return received
    async def forcefully_send_to_main_menu(self):
        await self.join(rooms[0])#main menu
        message = "Server: You are in the main menu now."
        await self.send_secure_message(message)
    async def leave_room(self):
        await self.current_room.broadcast_message(f"Server: User '{self.username}' has left the room({self.current_room.code}).")
        await self.join(rooms[0])#main menu
        message = "Server: You are in the main menu now."
        await self.send_secure_message(message)


class Room:
    def __init__(self, owner_name:str, code):
        self.owner_name = owner_name 
        self.code = code
        self.password = None
        self.members = []
        self.banned_members_usernames = []
        self.lock = asyncio.Lock()
    async def set_password(self, attempter:Client):
        async with self.lock:
            if attempter.username != self.owner_name:
                message = "Server: You don't have the authority to do that in this room."
                await attempter.send_secure_message(message)
                return
            if self.password != None:
                message = "Server: Enter current password"
                received_password_old = await attempter.prompt_and_get_response(message)
                if self.password != received_password_old:
                    message = "Server: Wrong password. To try again, run the command again."
                    await attempter.send_secure_message(message)
                    return
                message = "Server: Enter new password"
                received_password_new = await attempter.prompt_and_get_response(message)
                if received_password_new == received_password_old:
                    message = "Server: New password cannot be the same as old password."
                    await attempter.send_secure_message(message)
                    return
                self.password = received_password_new
                message = "Server: Password change successful"
                await attempter.send_secure_message(message)
                logger.debug(f"Password of room '{self.code}' owned by '{self.owner_name}' has been changed from '{received_password_old}' to '{self.password}', attempter was '{attempter.username}' with IP address '{attempter.ipaddress}'")
            else:
                message = "Server: Enter new password"
                received_password = await attempter.prompt_and_get_response(message)
                self.password = received_password
                message = "Server: Password was set successfully"
                await attempter.send_secure_message(message)
                logger.debug(f"Password of room '{self.code}' owned by '{self.owner_name}' was set to '{self.password}', attempter was '{attempter.username}' with IP address '{attempter.ipaddress}'")
    async def has_password(self):
        async with self.lock:
            return self.password is not None
    async def is_correct_password(self, password):
        async with self.lock:
            return password == self.password
    async def is_owned_by_user_with_username(self, client_username:str):
        async with self.lock:
            return client_username == self.owner_name
    async def add_member(self, client:Client):
        async with self.lock:
            self.members.append(client)
    async def remove_member(self, client:Client):
        async with self.lock:
            self.members.remove(client)
    async def client_is_in_room(self, client:Client):
        async with self.lock:
            return client in self.members
    async def list_members_to_client(self, client:Client):
        async with self.lock:
            members_copy = self.members[:]
        message = ""
        for cl in members_copy:
            message += cl.username + '\n'
        await client.send_secure_message(message)
    async def broadcast_message(self, message:str):
        async with self.lock:
            members_copy = self.members[:]
        for cl in members_copy:
            await cl.send_secure_message(message)
    async def kick_user_with_username(self, to_be_kicked_username):
        async with self.lock:
            members_copy = self.members[:]
        for cl in members_copy:
            if cl.username == to_be_kicked_username:
                message = f"You have been kicked from the room {self.code}. Sending you to main menu now..."
                await cl.send_secure_message(message)
                await cl.forcefully_send_to_main_menu()
                message = f"User '{to_be_kicked_username}' has been kicked from this room({self.code})."
                await self.broadcast_message(message)
                break
    async def kick_all_users_except_owner(self):
        async with self.lock:
            members_copy = self.members[:]
        for cl in members_copy:
            if cl.username != self.owner_name:
                message = f"You have been kicked from the room {self.code}. Sending you to main menu now..."
                await cl.send_secure_message(message)
                await cl.forcefully_send_to_main_menu()
                message = f"User '{cl.username}' has been kicked from this room({self.code})."
                await self.broadcast_message(message)
                break
    async def ban_user_with_username(self, to_be_banned_username:str):
        async with self.lock:
            self.banned_members_usernames.append(to_be_banned_username)
            members_copy = self.members[:]
        for cl in members_copy:
            if cl.username == to_be_banned_username:
                message = f"Server: You have banned from room {self.code} by {self.owner_name}."
                await cl.send_secure_message(message)
                await cl.forcefully_send_to_main_menu()
                break
        await self.broadcast_message(f"Server: {to_be_banned_username} has been banned from this room({self.code}).")
    async def has_banned_user_with_username(self, username:str):
        async with self.lock:
            return username in self.banned_members_usernames
    async def unban_user_with_username(self, username:str):
        async with self.lock:
            if username in self.banned_members_usernames:
                self.banned_members_usernames.remove(username)
                await self.broadcast_message(f"Server: {username} has been unbanned from this room({self.code}).")
            else:
                logger.error("User with username: {username} was tried to be unbanned from this room: {self.code}, reaching this message shouldn't be possible")
    async def close(self):
        async with rooms_lock:
            rooms.remove(self)
        await self.kick_all_users_except_owner()
        await self.kick_user_with_username(self.owner_name)


async def handle_client(reader, writer):
    addr, cliport = writer.get_extra_info('peername')
    logger.info(f"Received connection from ip address: '{addr}'")
    new_client = None
    username = None
    try:
        aes_key = await establish_secure_channel_and_get_aes_key(reader, writer)
        logger.info(f"Secure channel established with client '{addr}'.")

        username = await start_authentication_sequence(reader, writer, aes_key)
        new_client = Client(addr, username, reader, writer, aes_key)
        await new_client.async_init()
        async with client_list_lock:
            client_list.append(new_client)
        await receive_loop(new_client)

    except BaseException:
        if username is not None:
            logger.info(f"Lost connection with client with username: '{username}', ipaddress: '{addr}'")
        traceback.print_exc()
    finally:
        if new_client:
            async with client_list_lock:
                if new_client in client_list:
                    client_list.remove(new_client)
        writer.close()
        await writer.wait_closed()
        await write_nonce_to_log_file()


async def start_authentication_sequence(reader, writer, aes_key):
    addr, cliport = writer.get_extra_info('peername')
    logger.info(f"Starting authentication sequence with client '{addr}'.")

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
    while not ((username == "usertest" and password == "password") or (username == "ba2han" and password == "mypass")):
        logger.warning(f"Received wrong username:password pair '{username}:{password}'. Sender IP:'{addr}'")
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
            logger.warning(f"Client with IP Address:'{addr}' sent 3 wrong password requests, disconnecting user...")
            raise Exception("Too many wrong attempts")
    
    logger.info(f"client with IP address: '{addr}' logged in successfully with username: '{username}'")
    msg = "Server: Login successful."
    secure_msg = construct_secure_message(aes_key, msg)
    writer.write((secure_msg.to_json() + "\n").encode())
    await writer.drain()

    return username


async def establish_secure_channel_and_get_aes_key(reader, writer):
    addr, cliport = writer.get_extra_info('peername')
    data_bytes = await reader.readline()
    msg_obj = Message.from_json(data_bytes.decode())

    if msg_obj.type != "key_exchange":
        raise TypeError("Unexpected message type.")

    public_key_pem = msg_obj.payload["rsa_public_key"]
    logger.debug(f"Received public key from client with IP address '{addr}':\n{public_key_pem}")
    public_key = serialization.load_pem_public_key(public_key_pem.encode())

    aes_key = os.urandom(32)  # 256-bit AES key

    if not isinstance(public_key, RSAPublicKey):
        logger.warning(f"Received bad public key:\n{public_key}, Sender IP:\n{writer.get_extra_info('peername')}")
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

    msg_obj = Message(
        type="aes_key",
        payload={"encrypted_aes_key": encrypted_key_str}
    )

    json_str = msg_obj.to_json() + '\n'
    writer.write(json_str.encode())
    await writer.drain()

    return aes_key

async def receive_loop(client:Client):
    while True:
        message = await client.receive_secure_message()
        logger.debug(f"Received message: '{message}'\tfrom user with username: '{client.username}', and IP address : '{client.ipaddress}', in room: '{client.current_room.code}'")
        client_room = client.current_room
        if message.startswith('/'):
            await handle_command(client,message)
        else:
            message = f"{client.username}({client_room.code}): {message}"
            if not client_room.code == MAIN_MENU_CODE:
                await client_room.broadcast_message(message)
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
    if cmd == "message": ##very very bad solution, fix this asap
        msg = message[len(parts[0])+len(parts[1])+3:]
        await func(client, *args[:min_arg_count], msg)
    else:
        await func(client, *args[:min_arg_count])

#Commands start here

async def list_rooms_cmd(client:Client):
    message = ""
    async with rooms_lock:
        for room in rooms:
            message += f"{room.code}\n"
    await client.send_secure_message(message)

async def send_help_message_cmd(client:Client):
    message = """Server: \"To list the rooms already present use \'/list\' command.
    To join a room, use \'/join\'  e.g. \'/join #12345678\', (if the room has a password, you will have to provide one).
    If you wish to create a room, join a non-existing room and after entering use \'/setpasswd\' command to put a password to it if you wish.
    To exit the room you are in and return to main menu, use the \'/exitroom\' command.
    To receive this help message use the \'/help\' command.\""""
    await client.send_secure_message(message)

async def leave_room_cmd(client:Client):
    await client.leave_room()

MAX_ROOMS_PER_CLIENT = 3
async def join_room_cmd(client:Client, room_code):
    if not room_code.startswith('#') or len(room_code) != 9 or not room_code[1:].isalnum():
        await client.send_secure_message("Server: Room code must be in format '#12345678' and alphanumeric.")
        return
    async with rooms_lock:
        for room in rooms:
            if room_code == room.code:
                await client.join(room)
                return
    if client.owned_rooms_count < MAX_ROOMS_PER_CLIENT:
        await client.create_room(room_code)
    else:
        message = f"Server: You already own {MAX_ROOMS_PER_CLIENT} rooms, you can't create more."
        await client.send_secure_message(message)

async def set_room_password_cmd(client:Client):
    client_room = client.current_room
    if client_room.code == MAIN_MENU_CODE:
        message = "Server: You can't do that in the main menu."
        await client.send_secure_message(message)
    else:
        await client_room.set_password(client)

async def kick_all_users_except_owner_cmd(client:Client):
    r = client.current_room
    if not await r.is_owned_by_user_with_username(client.username):
        message = f"Server: You can't do that in the current room."
        await client.send_secure_message(message)
        return
    await r.kick_all_users_except_owner()

async def kick_user_with_username_cmd(client:Client, to_be_kicked_username:str):
    r = client.current_room
    if not await r.is_owned_by_user_with_username(client.username):
        message = f"Server: You can't do that in the current room."
        await client.send_secure_message(message)
        return
    if to_be_kicked_username == client.username:
        message = f"Server: You can't kick yourself. You can use the \'/exitroom\' command to exit the room."
        await client.send_secure_message(message)
        return
    await r.kick_user_with_username(to_be_kicked_username)

async def ban_user_with_username_cmd(client:Client, to_ban_username:str):
    r = client.current_room
    if not await r.is_owned_by_user_with_username(client.username): 
        message = f"Server: You can't do that in the current room."
        await client.send_secure_message(message)
        return
    if client.username == to_ban_username:
        message = f"Server: You can't ban yourself"
        await client.send_secure_message(message)
        return
    await r.ban_user_with_username(to_ban_username)

async def unban_user_with_username_cmd(client:Client, to_unban_username:str):
    r = client.current_room
    if await r.has_banned_user_with_username(to_unban_username):
        await r.unban_user_with_username(to_unban_username)
    else:
        message = f"There is no user with username '{to_unban_username}' that has been banned in this room."
        await client.send_secure_message(message)

async def list_members_cmd(client:Client):
    r = client.current_room
    await r.list_members_to_client(client)

async def send_direct_message_from_client_to_client_username_cmd(sender:Client, receiver_username:Client, message_from_sender:str):
    receiver_client = None
    async with client_list_lock:
        for client in client_list:
            if receiver_username == client.username:
                receiver_client = client
    if receiver_client is None:
        message = f"Server: No user with username '{receiver_username}' was found in the server."
        await sender.send_secure_message(message)
        return
    await receiver_client.send_secure_message(f"Direct messsage from {sender.username}: {message_from_sender}")
    await sender.send_secure_message(f"Sent to {receiver_username}: {message_from_sender}")

async def close_room_cmd(client:Client):
    client_room = client.current_room
    if not await client_room.is_owned_by_user_with_username(client.username):
        message = f"Server: You can't close a room you don't own."
        await client.send_secure_message(message)
        return
    await client_room.close()
        

commands = {
    #"{command_name}":(func_name, num_of_args)
    "listrooms":(list_rooms_cmd, 0),
    "help":(send_help_message_cmd, 0),
    "join":(join_room_cmd, 1),
    "setpasswd":(set_room_password_cmd, 0),
    "exit":(leave_room_cmd, 0),
    "listmembers":(list_members_cmd, 0),
    "kickall":(kick_all_users_except_owner_cmd, 0),
    "closeroom":(close_room_cmd, 0),
    "kick":(kick_user_with_username_cmd, 1),
    "ban":(ban_user_with_username_cmd, 1),
    "unban":(unban_user_with_username_cmd, 1),
    "message":(send_direct_message_from_client_to_client_username_cmd, 1) 
}

#Commands end here

async def receive_secure_message_and_log(reader: asyncio.StreamReader, writer : asyncio.StreamWriter, aes_key: bytes, max_delay_sec=5) -> str:
    addr, cliport = writer.get_extra_info('peername')
    data = await reader.readline()
    if not data:
        raise ConnectionError("Connection closed by peer.")

    msg = Message.from_json(data.decode())

    nonce_bytes = base64.b64decode(msg.nonce)

    await log_nonce(nonce_bytes, writer)

    ciphertext_bytes = base64.b64decode(msg.payload["ciphertext"])
    tag_bytes = base64.b64decode(msg.payload["tag"])
    timestamp = msg.timestamp
    received_hmac = base64.b64decode(msg.hmac)

    current_time = int(time.time())
    if abs(current_time - timestamp) > max_delay_sec:
        logger.warning(f"Received message with timestamp earlier or later than {max_delay_sec} of current time: '{data.decode()}', Sender IP address: '{addr}'")
        raise ValueError("Bad Message Timestamp")
    
    data_to_auth = (
        base64.b64encode(nonce_bytes).decode() +
        base64.b64encode(ciphertext_bytes).decode() +
        base64.b64encode(tag_bytes).decode() +
        str(timestamp)
    ).encode()

    expected_hmac = hmac.new(aes_key, data_to_auth, hashlib.sha256).digest()

    if not hmac.compare_digest(received_hmac, expected_hmac):
        logger.warning(f"HMAC authentication of message: '{data.decode()}' failed. Sender IP address: '{addr}'")
        raise ValueError("HMAC authentication failed.")

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce_bytes, tag_bytes))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext_bytes) + decryptor.finalize()

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


NONCE_LIVE_TIME_MAX = 30 #how long the nonce stays in memory

async def log_nonce(nonce_bytes: bytes, writer: asyncio.StreamWriter):
    new_nonce_hex = nonce_bytes.hex()
    async with nonce_lock:

        if new_nonce_hex in nonce_dict:
            addr, cliport = writer.get_extra_info('peername')
            logger.warning(f"Replay attack detected from '{addr}' with nonce: '{nonce_bytes}'")
            raise ValueError("Bad Nonce")

        current_time = int(time.time())
        to_remove = []
        
        for nonce_hex, timestamp in nonce_dict.items():
            if current_time - timestamp > NONCE_LIVE_TIME_MAX:
                to_remove.append(nonce_hex)

        for nonce_hex in to_remove:
            del nonce_dict[nonce_hex]
        
        nonce_dict[new_nonce_hex] = current_time
    
async def write_nonce_to_log_file():
    async with nonce_lock:
        logger.debug(f"NONCE ENTRIES ------------------------------------------------------------------------")
        for nonce_hex, timestamp in nonce_dict.items():
            logger.debug(f"NONCE: {nonce_hex}, TIMESTAMP: {timestamp}")
        logger.debug(f"NONCE ENTRIES OVER--------------------------------------------------------------------")



async def main():
    main_menu = Room("", MAIN_MENU_CODE)
    async with rooms_lock: #not sure if needed
        rooms.append(main_menu)

    server = await asyncio.start_server(handle_client, HOST_IP, HOST_PORT)
    logger.info(f"Server started listening on '{HOST_IP}':'{HOST_PORT}'")
    async with server:
        await server.serve_forever()

asyncio.run(main())
