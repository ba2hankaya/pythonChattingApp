import asyncio
import sys
import os
import curses
import traceback

#RECEIVE_WINDOW_PARAMS
r_begin_x = 1
r_begin_y = 1
r_height = 30
r_width = 200

#INPUT_WINDOW_PARAMS
i_begin_x = 1
i_begin_y = 32
i_height = 3
i_width = 200


class NonBlockingInput:
    def __init__(self, inputwin, backendwriter):
        self.inputwin = inputwin 
        self.backendwriter = backendwriter
        self.s = ""
    async def build_input(self):
        self.redraw()
        key = self.inputwin.getch()
        if key == curses.ERR:
            return
        elif key in (curses.KEY_ENTER, 10, 13):
            await send_msg(self.backendwriter, self.s)
            self.s = ""
        elif key in (curses.KEY_BACKSPACE, 127):
            if len(self.s) > 0:
                self.s = self.s[:-1]
        elif 32 <= key <= 126:
            self.s += str(chr(key))

    def redraw(self):
        self.inputwin.clear()
        self.inputwin.box()
        self.inputwin.addstr(1, 1, self.s)
        self.inputwin.refresh()
        

class OutputReceived:
    def __init__(self, receivewin):
        self.receivewin = receivewin
        self.messages = []

    def add_message(self, message):
        if message == "":
            return
        self.messages.append(message)
        if len(self.messages) == r_height - 1:
            self.messages.pop(0)
        self.redraw()

    def redraw(self):
        self.receivewin.clear()
        self.receivewin.box()
        self.output()
        self.receivewin.refresh()

    def output(self):
        curY = 1
        for message in self.messages:
            self.receivewin.addstr(curY, 1, message)
            curY +=1 
    
server_task = None
server_is_closed = False

async def main():
    server = await asyncio.start_server(handle_comms, '127.0.0.1' , 33445)
    #script_path = os.path.join(os.path.dirname(__file__), 'client.py')
    #print("Starting backend process...")
    #backend_proc = await asyncio.create_subprocess_exec(
    #    sys.executable, script_path,
    #    stdout=asyncio.subprocess.PIPE,
    #    stderr=asyncio.subprocess.PIPE
    #)
    global server_task
    server_task = asyncio.create_task(server.serve_forever())
    try:
        await server_task
    except asyncio.CancelledError:
        pass

async def handle_comms(reader, writer):
    stdscr = None
    try:
        serverip = input("Enter server ip: ")
        port = input("Enter server port: ")

        writer.write((serverip + '\n').encode())
        await writer.drain()

        writer.write((port + '\n').encode())
        await writer.drain()

        stdscr = curses.initscr()

        receivewin = curses.newwin(r_height, r_width, r_begin_y, r_begin_x)
        inputwin = curses.newwin(i_height, i_width, i_begin_y, i_begin_x)
        inputwin.box()
        inputwin.nodelay(True)
        receivewin.box()
        await asyncio.gather(
                receive_loop(reader, receivewin),
                send_loop(inputwin, writer)
        )
    except BaseException:
        global server_is_closed
        server_is_closed = True
        if stdscr is not None:
            stdscr.clear()
            stdscr.refresh()
            stdscr.move(0,0)
            curses.endwin()
        traceback.print_exc()
        if server_task is not None:
            server_task.cancel()
    finally:
        writer.close()
        await writer.wait_closed()

async def receive_loop(backendreader, receivewin):
    outrecv = OutputReceived(receivewin)
    while True:
        if server_is_closed:
            break
        data = await backendreader.readline()
        if not data:
            raise ConnectionError("back end disconnected")
        message = data.decode().strip()
        outrecv.add_message(message)

async def send_msg(backendwriter, msg):
        backendwriter.write((msg + '\n').encode())
        await backendwriter.drain()


async def send_loop(inputwin, backendwriter):
    nbi = NonBlockingInput(inputwin, backendwriter)
    while True:
        if server_is_closed:
            break
        await nbi.build_input()
        await asyncio.sleep(0.05)

asyncio.run(main())
