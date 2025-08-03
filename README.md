# pythonChattingApp

My attempt at a secure chatting app in python for learning purposes.
It uses async programming as opposed to threads like my previous attempts at chatting apps. It also has manual encryption added established through RSA and AES keys.
It is a room based server where you can chat with people that are in the same room as you. There is a backend and frontend for the client application and a server.
The backend and frontend are connected through a tcp connection and so are the client and server. The purpose of this project was to learn how client applications' frontend and backend interact with eachother, develop a curses ui in terminal that doesn't block the program, create a server that can handle multiple clients, learn async programming, and ultimately make a similar chatting app to one I had seen in Mr. Robot :)
