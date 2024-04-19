import socket, sys, threading

stopThread  = False

def main():
    ''' RUNS MAIN PROGRAM, gets password and client name from user, connects to server, and starts receive thread.'''

    global userName, password, client
    userName = input ("[!] Enter your username: ")
    if userName == "":
        print("[ERROR] Please enter a valid username")
    if userName == "admin":
        password = input("[!] Enter your password: ")
        if password == "":
            print("[ERROR] Please enter a valid password")

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0,1', 8080))


def receiveHandler():
    while True:
        global stopThread
        if stopThread:
            break
        try:
            message = client.recv(1024).decode('ascii')
            print("[MESSAGE] -- CLIENT " + message)
            if message == "USER":
                client.send(userName.encode('ascii'))
                nextMessage = client.recv(1024).decode('ascii')
                print("[MESSAGE] -- CLIENT " + nextMessage)

                if nextMessage == "PASS":
                    client.send(password.encode('ascii'))
                    if client.recv(1024).decode('ascii') == "REFUSE":
                        print("[ERROR] Connection was refused! Please enter a valid password.")
                        stopThread = True

                # CHECKS IF ADMIN SETS KICK OR BAN SIGNAL
                elif nextMessage == "BAN":
                    print("[ERROR] Connection refused because of ban.")
                    client.close()
                    stopThread = True

                elif nextMessage == "KICK":
                    print("[ERROR] Connection was kicked by admin.")
                    client.close()
                    stopThread = True

            else:
                print("[!] CLIENT MESSAGE " + message)
        except sys.exception as e:
            print("[ERROR] An error occurred!" + str(e))
            client.close()
            break


def writeHandler():
    while True:
        if stopThread:
            client.close()
            break


        ''' CODE TO CHECK IF USER NAME == ADMIN, WHICH GRANTS KICK AND BAN PRIVILEGES.'''
        message = f"{userName}: {input('')}"
        if message[len(userName)+2:].startswith('/'):
            if userName == "admin":
                if message[len(userName)+2:].startswith('/kick'):
                    client.send(f"KICK {message[len(userName)+2+6:]}".encode('ascii'))
                elif message[len(userName)+2:].startswith('/ban'):
                    client.send(f"BAN {message[len(userName)+2+5:]}".encode('ascii'))
            else:
                print("[ERROR] You do not have permission to use this command.")
        else:
            client.send(message.encode('ascii'))
            print("[MESSAGE] -- CLIENT " + message)
        client.send(message.encode('ascii'))




if __name__ == '__main__':

    try:
        main()
        receivingThread = threading.Thread(target=receiveHandler)
        writingThread = threading.Thread(target=writeHandler)

        writingThread.start()
        receivingThread.start()

    except Exception as e:
        print("[ERROR] An error occurred! IN MAIN " + str(e))


