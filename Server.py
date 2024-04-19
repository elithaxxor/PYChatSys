import socket, sys, threading


host = "127.0.0.1"
port = 8080
S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
S.bind((host, port))
S.listen()

clientList = []
usernames = []

stopThread = False

'''Broadcasts message to all clients in clientList'''
def broadcastHandler(message):
    for client in clientList:
        client.send(message)

def mainHandler(client):
    '''Handles the main functionality of the server, checks if message is a kick or ban, and kicks or bans user accordingly.'''
    while True:
        try:
            message = client.recv(1024)
            broadcastHandler(message)
            ''' DECODES MESSAG to SEE IF KICK OR BAN IS PARSED '''
            if message.decode('ascii').startswith("KICK"):
                nameToKick = message.decode('ascii')[5:]
                kickUser(nameToKick)

            elif message.decode('ascii').startswith("BAN"):
                nameToBan = message.decode('ascii')[4:]
                kickUser(nameToBan)
                print(f"[!] {nameToBan} was banned!")
                with open("bans.txt", 'a') as f:
                    f.write(f"{nameToBan}\n")
                    nameToKick = message.decode('ascii')[5:]
                    kickUser(nameToKick)
                    print(f"[!] KICKING {nameToKick} !")
                pass
            else:
                # IF NO KICK OR BAN, BROADCAST MESSAGE
                broadcastHandler(message)

        except Exception as e:
            print("[ERROR] An error occurred!" + str(e))
            idx = clientList.index(client)
            clientList.remove(client)
            client.close()
            clientList.remove(client)
            broadcastHandler(f"[!] {usernames[idx]} has left the chat!".encode('ascii'))
            break

def receiveHandler():
    '''Handles the receiving of messages from the client.'''
    while True:
        global stopThread
        if stopThread:
            break

        try:
            client, address = S.accept()
            print(f"[!] {str(address)} has connected.")
            client.send("USER".encode('ascii'))
            username = client.recv(1024).decode('ascii')

            ## checks if username is in the banned list, if so, refuse connection.
            with open("bans.txt", 'r') as f:
                bans = f.readlines()

            if username + "\n" in bans:
                client.send("BAN".encode('ascii'))
                client.close()
                continue

            ## checks if username is admin, if so, ask for password.
            if username == "admin":
                client.send("PASS".encode('ascii'))
                password = client.recv(1024).decode('ascii')

                if password != "adminpass":
                    client.send("REFUSE".encode('ascii'))
                    print(f"[!] {username} has failed to connect due to incorrect password.")
                    client.send("REFUSE".encode('ascii'))
                    # clientList.remove(client)
                    client.close()
                    continue

            # if username is not in banned list, or is not admin, add username to list and client to clientList.
            usernames.append(username)
            clientList.append(client)
            print(f"[!] {username} has joined the chat!")
            broadcastHandler(f"[!] {username} has joined the chat!".encode('ascii'))
            client.send("Connected to server!".encode('ascii'))
            print(f"[!] {username} has joined the chat!")
            thread = threading.Thread(target=mainHandler, args=(client,))
            thread.start()
        except Exception as e:
            print("[ERROR] An error occurred!" + str(e))
            # stopThread = True

def kickUser(userName):
    if userName in usernames:
        # calculates the index of the user to kick, then pulls user index from clientList to kick user. and removes user from clientList.

        userIndex = usernames.index(userName)
        userToKick = clientList[userIndex]
        clientList.remove(userToKick)
        userToKick.send("[!] You were kicked by admin.".encode('ascii'))
        userToKick.close()
        usernames.remove(userName)
        broadcastHandler(f"[!] {userName} was kicked by admin.".encode('ascii'))
        print(f"[!] [KICK USER PARSED] \n {userName} was kicked by admin.".encode('ascii'))

if __name__ == '__main__':
    while True:
        client, address = S.accept()
        print(f"[!] {str(address)} has connected.")
        client.send("USER".encode('ascii'))
        username = client.recv(1024).decode('ascii')
        usernames.append(username)
        clientList.append(client)
        print(f"[!] {username} has joined the chat!")
        broadcastHandler(f"[!] {username} has joined the chat!".encode('ascii'))
        client.send("Connected to server!".encode('ascii'))
        thread = threading.Thread(target=mainHandler, args=(client,))
        thread.start()