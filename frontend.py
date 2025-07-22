import asyncio
import sys
import os

async def main():
    server = await asyncio.start_server(handle_comms, '127.0.0.1' , 33445)

    #script_path = os.path.join(os.path.dirname(__file__), 'client.py')
    #print("Starting backend process...")
    #backend_proc = await asyncio.create_subprocess_exec(
    #    sys.executable, script_path,
    #    stdout=asyncio.subprocess.PIPE,
    #    stderr=asyncio.subprocess.PIPE
    #)

    async with server:
        await server.serve_forever()

async def handle_comms(reader, writer):
    await asyncio.gather(
            receive_loop(reader),
            send_loop(writer)
    )

async def receive_loop(backendreader):
    try:
        while True:
            data = await backendreader.readline()
            if not data:
                print("backend disc")
                sys.exit()
            message = data.decode()
            print(f"received from backend: {message}")
    except (ConnectionError, asyncio.IncompleteReadError, asyncio.CancelledError):
        print("connection to backend was lost while receiveing")

async def send_loop(backendwriter):
    try:
        while True:
            userinput = await asyncio.to_thread(input, "message: ")
            backendwriter.write((userinput + '\n').encode())
            await backendwriter.drain()
    except(ConnectionError, asyncio.CancelledError):
        print("connection to backend was lost while sending")

asyncio.run(main())
