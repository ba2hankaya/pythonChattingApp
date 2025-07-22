import asyncio
import os
import time
import base64
import hmac
import hashlib
import sys

from message import Message

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class ClientContext:
    def __init__(self):
        self.frontendreader = None
        self.frontendwriter = None
        self.backendreader = None
        self.backendwriter = None
        self.aes_key = None


async def main():
    ctx = ClientContext()
    frontendip = '127.0.0.1'
    frontendport = 33445
    ctx.frontendreader, ctx.frontendwriter = await asyncio.open_connection(frontendip, frontendport)
    serverip = (await ctx.frontendreader.readline()).decode().strip()
    print(f"\'{serverip}\'")
    serverport = int((await ctx.frontendreader.readline()).decode().strip())
    print(f"\'{serverip}\'")
    await connect_with_server(serverip, serverport, ctx)


async def connect_with_server(ipaddr , port, ctx:ClientContext):
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
    print("Sent public key")

    # Receive AES key from server
    data = await ctx.backendreader.readline()
    msg = Message.from_json(data.decode())

    if msg.type != "aes_key":
        print("Did not receive AES key")
        sys.exit()

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

    print("Secure channel established")
    await asyncio.gather(
        front_end_receive_loop(ctx),
        receive_loop(ctx)
    )

    ctx.backendwriter.close()
    await ctx.backendwriter.wait_closed()

async def receive_loop(ctx: ClientContext):
    try:
        while True:
            message = await receive_secure_message(ctx)
            print(f"\n[Received from server] {message}")
            await front_end_send_message(message, ctx)
    except (ConnectionError, asyncio.IncompleteReadError, asyncio.CancelledError):
        print("Receive loop ended (disconnected).")

async def front_end_send_message(message, ctx: ClientContext):
    try:
        ctx.frontendwriter.write((message + '\n').encode())
        await ctx.frontendwriter.drain()
    except (ConnectionError, asyncio.CancelledError):
            print("front end send loop ended (disconnected).")


async def front_end_receive_loop(ctx:ClientContext):
    try:
        while True:
            data = await ctx.frontendreader.readline()
            message = data.decode()
            print(f"\n[Received from front end] {message}")
            await send_to_server(message, ctx)
    except (ConnectionError, asyncio.IncompleteReadError, asyncio.CancelledError):
        print("Frontend receive loop ended (disconnected).")


async def send_to_server(msg, ctx: ClientContext):
    try:
        secure_msg = construct_secure_message(ctx,msg)
        ctx.backendwriter.write((secure_msg.to_json() + "\n").encode())
        await ctx.backendwriter.drain()
    except (ConnectionError, asyncio.CancelledError):
        print("Send loop ended (disconnected).")


    

async def receive_secure_message(ctx:ClientContext, max_delay_sec=5) -> str:
    data = await ctx.backendreader.readline()
    if not data:
        raise ConnectionError("Connection closed by peer.")

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
        raise ValueError("HMAC authentication failed.")

    cipher = Cipher(algorithms.AES(ctx.aes_key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext.decode()


def construct_secure_message(ctx: ClientContext,plaintext: str) -> Message:
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
