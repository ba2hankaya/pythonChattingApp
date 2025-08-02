import asyncio
import os
import time
import base64
import hmac
import hashlib
import sys
import traceback

from message import Message

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

import logging

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

fileHandler = logging.FileHandler('client_backend.log')
fileHandler.setLevel(logging.INFO)

fileHandler2 = logging.FileHandler('client_backend.debug.log')
fileHandler2.setLevel(logging.DEBUG)

consoleHandler = logging.StreamHandler()
consoleHandler.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s\t%(levelname)s\t%(message)s')

fileHandler.setFormatter(formatter)
fileHandler2.setFormatter(formatter)
consoleHandler.setFormatter(formatter)

logger.addHandler(fileHandler)
logger.addHandler(fileHandler2)
#use only when debugging separately, otherwise will mess with front end's ui
#logger.addHandler(consoleHandler)

server_task = None
server_is_closed = False
FRONT_END_IP = '127.0.0.1'
FRONT_END_PORT = 33445

class ClientHandler:
    def __init__(self):
        self.frontendreader: asyncio.StreamReader = None
        self.frontendwriter: asyncio.StreamWriter = None
        self.backendreader: asyncio.StreamReader = None
        self.backendwriter: asyncio.StreamWriter = None
        self.aes_key: bytes = None
    async def handle_comms(self, reader, writer):
        try:
            self.frontendreader = reader
            self.frontendwriter = writer

            await self.send_message_to_frontend("Server ip: ")
            data = await self.frontendreader.readline()
            backend_server_ip = data.decode().strip()

            await self.send_message_to_frontend("Server port: ")
            data = await self.frontendreader.readline()
            backend_server_port = data.decode().strip()
            
            await connect_with_server(backend_server_ip, backend_server_port, self)
        except BaseException:
            traceback.print_exc()
        finally:
            self.frontendwriter.close()
            await self.frontendwriter.wait_closed()
            global server_is_closed
            server_is_closed = True
            if server_task is not None:
                server_task.cancel()

    async def send_message_to_frontend(self, message):
        self.frontendwriter.write((message + '\n').encode())
        await self.frontendwriter.drain()
        logger.debug(f"Sent message to frontend: '{message}'")

    async def front_end_receive_loop(self):
        while True:
            if server_is_closed:
                break
            data_bytes = await self.frontendreader.readline()
            if not data_bytes:
                raise ConnectionError("Frontend closed connection")
            message = data_bytes.decode().strip()
            logger.debug(f"Received message from frontend: '{message}'")
            await self.send_message_to_backend(message)

    async def send_message_to_backend(self, message):
        secure_msg = construct_secure_message(self,message)
        self.backendwriter.write((secure_msg.to_json() + "\n").encode())
        await self.backendwriter.drain()
        logger.debug(f"Sent message to backend: '{message}'")

    async def backend_receive_loop(self):
        while True:
            if server_is_closed:
                break
            message = await receive_secure_message(self)
            logger.debug(f"Received message from backend: '{message}'")
            await self.send_message_to_frontend(message)


async def main():
    cl_handler = ClientHandler()
    server = await asyncio.start_server(cl_handler.handle_comms, FRONT_END_IP, FRONT_END_PORT)
    global server_task
    server_task = asyncio.create_task(server.serve_forever())
    try:
        await server_task
    except:
        pass

async def connect_with_server(ipaddr , port, ctx:ClientHandler):
    logger.info(f"Trying to connect to server with ip address: '{ipaddr}:{port}'")
    ctx.backendreader, ctx.backendwriter = await asyncio.open_connection(ipaddr, port)

    # Generate RSA key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Send public key
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    msg = Message(
        type="key_exchange",
        payload={"rsa_public_key": pem}
    )

    json_str = msg.to_json() + '\n'
    ctx.backendwriter.write(json_str.encode())
    await ctx.backendwriter.drain()
    logger.info(f"Sent public key: {pem}")

    # Receive AES key from server
    data = await ctx.backendreader.readline()
    msg = Message.from_json(data.decode())

    if msg.type != "aes_key":
        logger.warning(f"Was expecting message with type 'aes_key'. Instead got: {msg}")
        raise Exception("Did not receive AES key message type")

    encrypted_key_str = msg.payload["encrypted_aes_key"]
    encrypted_aes_key = base64.b64decode(encrypted_key_str)

    ctx.aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    logger.info("Secure channel established")
    await asyncio.gather(
        ctx.front_end_receive_loop(),
        ctx.backend_receive_loop()
    )

async def receive_secure_message(ctx:ClientHandler, max_delay_sec=5) -> str:
    data = await ctx.backendreader.readline()
    if not data:
        raise ConnectionError("Connection closed by server.")

    msg = Message.from_json(data.decode())

    nonce = base64.b64decode(msg.nonce)
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

    expected_hmac = hmac.new(ctx.aes_key, data_to_auth, hashlib.sha256).digest()

    if not hmac.compare_digest(received_hmac, expected_hmac):
        logger.warning(f"Received false hmac. Message = {msg}.")
        raise ValueError("HMAC authentication failed.")

    cipher = Cipher(algorithms.AES(ctx.aes_key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext.decode()


def construct_secure_message(ctx: ClientHandler,plaintext: str) -> Message:
    nonce = os.urandom(12)

    cipher = Cipher(algorithms.AES(ctx.aes_key), modes.GCM(nonce))
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

    hmac_digest = hmac.new(ctx.aes_key, data_to_auth, hashlib.sha256).digest()
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


asyncio.run(main())
