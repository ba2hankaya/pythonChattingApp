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


async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    print(f"Connection from {addr}")

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

    print("Secure channel established.")
    await asyncio.gather(
        send_loop(writer, aes_key),
        receive_loop(reader, aes_key)
    )

    writer.close()
    await writer.wait_closed()


async def send_loop(writer, aes_key):
    try:
        while True:
            msg = await asyncio.to_thread(input, "> ")
            secure_msg = construct_secure_message(aes_key, msg)
            writer.write((secure_msg.to_json() + "\n").encode())
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        print("Send loop ended.")


async def receive_loop(reader, aes_key, max_delay_sec=5):
    try:
        while True:
            message = await receive_secure_message(reader, aes_key, max_delay_sec)
            print(f"\n[Received] {message}")
    except (ConnectionError, asyncio.IncompleteReadError, asyncio.CancelledError):
        print("Receive loop ended.")


async def receive_secure_message(reader: asyncio.StreamReader, aes_key: bytes, max_delay_sec=5) -> str:
    data = await reader.readline()
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

import time
import asyncio

NONCE_AWAIT_TIME = 30  # or whatever your nonce window is

def logNonce(nonce: str, writer: asyncio.StreamWriter):
    try:
        with open("log.txt", "r") as f:
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

    with open("log.txt", "w") as f:
        for line in new_lines:
            f.write(f"{line}\n")



async def main():
    server = await asyncio.start_server(handle_client, host, port)
    print(f"Server listening on {host}:{port}")
    async with server:
        await server.serve_forever()

asyncio.run(main())
