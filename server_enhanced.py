'''
CMPT361 Group Project
Group Members - Will Lorentz, Jordan Wolski, Knight McLaughlin

Purpose - This is the server side of a secure mail application.
'''

import socket
import os
import sys
import json
import glob
import datetime

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def server():
    #Server port
    serverPort = 13001
    
    #Create server socket that uses IPv4 and TCP protocols 
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in server socket creation:',e)
        sys.exit(1)
    
    #Associate 12000 port number to the server socket
    try:
        serverSocket.bind(('', serverPort))
    except socket.error as e:
        print('Error in server socket binding:',e)
        sys.exit(1)        
        
    print('The server is ready to accept connections')
        
    #The server can only have one connection in its queue waiting for acceptance
    serverSocket.listen(5)
        
    while 1:
        try:
            #Server accepts client connection
            connectionSocket, addr = serverSocket.accept()

            pid = os.fork()

            if pid == 0:
                
                sPrivate = RSA.import_key(open("server_private.pem").read())

                #recieve credentials and validate
                message = connectionSocket.recv(2048)
                decryptor = PKCS1_OAEP.new(sPrivate)
                rawMessage = decryptor.decrypt(message).decode("ascii")
                
                isValid, nonce = validateUser(rawMessage)
                print("Clients nonce is: " + nonce)
                clientNum = rawMessage.split(":")

                #disconnect if invalid
                if not isValid:
                    message = "Invalid username or password"
                    connectionSocket.send(message.encode("ascii"))
                    print(f"The recieved client information: {clientNum[0]} is invalid (Connection Terminated).")
                    connectionSocket.close()
                
                else:
                    clientNum = clientNum[0]
                    clientNum = clientNum[-1::]
                    sym_key = get_random_bytes(32)
                    cPublic = RSA.import_key(open(f"client{clientNum}_public.pem").read())
                    encryptor = PKCS1_OAEP.new(cPublic)
                    
                    #send User Valid
                    message = "Valid User"
                    connectionSocket.send(message.encode("ascii"))
                    print(f"Connection accepted and symmetric key generated for client: client{clientNum}")
                    
                    #encrypt with client public key
                    encryptedNonce = encryptor.encrypt(nonce.encode("ascii"))
                    #send back encrypted R
                    print("Sending back encrypted nonce.")
                    connectionSocket.send(encryptedNonce)
                    #get response and send sym_key
                    message = connectionSocket.recv(2048)
                    rawMessage = decryptor.decrypt(message).decode("ascii")

                    if rawMessage == "Nonce OK":
                        message = encryptor.encrypt(sym_key)
                        #send AES 256bit key
                        connectionSocket.send(message)
                    else:
                        connectionSocket.close()
    
                cipher = AES.new(sym_key, AES.MODE_ECB)
                message = connectionSocket.recv(2048)
                message = unpad(cipher.decrypt(message), 16).decode("ascii")
    
                running = 1
                while running:
                    
                    #send menu
                    message = "Select the operation:\n\t1) Create and send an email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4) Terminate the connection\n\n\tchoice: "
                    message = cipher.encrypt(pad(message.encode("ascii"), 16))
                    connectionSocket.send(message)

                    #recieve choice
                    choice = connectionSocket.recv(2048)
                    choice = unpad(cipher.decrypt(choice), 16).decode("ascii")

                    #send e-mail
                    if choice == "1":
                        emailConfirm = "Send the email"
                        emailCrypt = cipher.encrypt(pad(emailConfirm.encode('ascii'),16))
                        connectionSocket.send(emailCrypt)
                        
                        emailMessage = connectionSocket.recv(2048)
                        #dateTime = datetime.datetime.now()
    
                        emailMessage = unpad(cipher.decrypt(emailMessage), 16).decode("ascii")
                        
                        if emailMessage == "Error":
                            continue
                        messageReceived(emailMessage)
                    
                    #display e-mails
                    elif choice == "2":
                        mailList = getSortedMailList(clientNum)
                        mailList = formatMailList(mailList)
                        mailList = cipher.encrypt(pad(mailList.encode('ascii'), 16))
                        connectionSocket.send(mailList)

                    #view e-mail
                    elif choice == "3":
                        emailIndex = "the server request email index"
                        IndexCrypt = cipher.encrypt(pad(emailIndex.encode('ascii'),16))
                        connectionSocket.send(IndexCrypt)
                        wantedFile = connectionSocket.recv(2048)
                        wantedFile = unpad(cipher.decrypt(wantedFile), 16).decode("ascii")   
                        #if Error is recieved do not try to find email
                        if wantedFile == "Error":
                            continue
                        retrievedEmail = getMessage(wantedFile, clientNum)
                        retrievedCrypt = cipher.encrypt(pad(retrievedEmail.encode('ascii'),16))
                        connectionSocket.send(retrievedCrypt)                    
                    
                    #disconnect
                    elif choice == "4":
                        print(f"Terminating connection with client{clientNum}")
                        break
                                        
                
                connectionSocket.close()
                
                return
            
            #Parent doesn't need this connection
            connectionSocket.close()
            
        except socket.error as e:
            print('An error occured:',e)
            serverSocket.close() 
            sys.exit(1)        
        except:
            serverSocket.close() 
            sys.exit(0)


def getMessage(filename, num):
    emailFile = open("client" + num + "/" + filename + ".txt", "r")
    return emailFile.read()


def messageReceived(emailMessage):
    dateTime = datetime.datetime.now()
    listMessage = emailMessage.split("\n")
    
    if (len(listMessage[5]) >= 1000000) or (len(listMessage[2][7:]) >= 100):
        return
    
    formatedMessage = "An email from {} is sent to {} has a content length of {}".format(listMessage[0][6:], listMessage[1][4:], listMessage[3][16:])

    
    contentMessageSplit = listMessage[5:]
    contentMessage = ""
    c = 0
    for text in contentMessageSplit:
        if c == 0:
            contentMessage = contentMessage + text
            c += 1
        else:
            contentMessage = contentMessage + "\n" + text
        
    storedEmail = "{}\n{}\nTime and Date: {}\n{}\n{}\n{}\n{}".format(listMessage[0], listMessage[1], dateTime, listMessage[2], listMessage[3], listMessage[4], contentMessage)
    
    destList = listMessage[1][4:].split(";")

    for dest in destList:
        inputFile = open(dest + "/" + listMessage[0][6:] + "_" + listMessage[2][7:] + ".txt", "w")
        inputFile.write(storedEmail)
        inputFile.close()
    
    return


def formatMailList(mailList):
    '''
    Function returns a formatted string of the mail list.

    Params - mailList - iter - nested list of all mail items.
    Return - inbox - str - formatted string.
    '''
    inbox = "Index     From           DateTime                      Title\n"
    for mail in mailList:
        inbox += mail[0] + " " * (10 - len(mail[0]))
        inbox += mail[1] + " " * (15 - len(mail[1]))
        inbox += mail[2] + " " * (30 - len(mail[2]))
        inbox += mail[3] + " " * (100 - len(mail[3]))
        inbox += "\n"
    
    return inbox


def getSortedMailList(clientNum):
    '''
    Function searches the proper user inbox and stores
    the e-mail data in a return list.

    params - clientNum - int - number associated with the client.
    return - retArray - iter - nested list of mail data.
    '''
    client = f"client{clientNum}"
    mailList = os.listdir(client)
    retArray = []
    index = 1

    for mail in mailList:
        with open(f"{client}/{mail}", 'r') as f:
            data = f.readlines()
            sender = data[0][6:-1]
            time = data[2][15:-1]
            title = data[3][7:-1]
            message = []
            message.append(f"{index}")
            message.append(sender)
            message.append(time)
            message.append(title)
        retArray.append(message)
        index += 1

    retArray.sort(key = lambda x: x[2])
    return retArray


def validateUser(creds):
    '''
    Function compares credentials to password file.

    Params - creds - ("username:password:nonce")
    Return - bool - true if valid. false if invalid
    '''

    credList = creds.split(":")

    try:
        with open("user_pass.json", "r+") as file:
            jsonDict = json.load(file)
            for key, value in jsonDict.items():
                if credList[0] == key:
                    if credList[1] == value:
                        return 1,credList[2]
    except:
        print("Password file does not exist")

    return 0,0

#-------
server()



