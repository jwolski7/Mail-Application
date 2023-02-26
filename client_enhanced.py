'''
Purpose - This is the client side of a secure mail application.
'''

import socket
import os
import sys

import json
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

def client():

    serverName = input("Enter the server host name of IP: ")
    if serverName == "":
        serverName = "127.0.0.1"
    serverPort = 13001

    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print("Error in client socket creation", e)
        sys.exit(1)

    try:
        clientSocket.connect((serverName, serverPort))

        uName = input("Enter your username: ")
        pWord = input("Enter your password: ")

        #add nonce to credentials 
        nonce = str(get_random_bytes(16))
        print("Current nonce is: " + nonce)
        creds = (uName + ":" + pWord + ":" + nonce).encode("ascii")

        sPublic = RSA.import_key(open("server_public.pem").read())
        encryptor = PKCS1_OAEP.new(sPublic)
        message = encryptor.encrypt(creds)

        #send credentials
        clientSocket.send(message)

        #recieve key or invalid user
        message = clientSocket.recv(2048)
        invalid = ""
        rawMessage = ""
        
        invalid = message.decode("ascii")


        clientNum = uName[-1::]
        cPrivate = RSA.import_key(open(f"client{clientNum}_private.pem").read())
        decryptor = PKCS1_OAEP.new(cPrivate)
        #rawMessage = decryptor.decrypt(message)
        
        if invalid == "Invalid username or password":
            print(invalid + "\nTerminating.")
            clientSocket.close()

        else:
            #recieve and decrypt R with client private key
            encryptedNonce = clientSocket.recv(2048)
            recievedNonce = decryptor.decrypt(encryptedNonce).decode("ascii")
            #if ok, request sym_key
            if nonce == recievedNonce:
                print("The nonce from the server is: " + recievedNonce + "\nSuccess, the nonces match. Connection is secure.")
                clientSocket.send(encryptor.encrypt("Nonce OK".encode("ascii")))
            else:
                print("The nonce from the server is: " + recievedNonce + "\nThe nonces do not match. The connection is not secure. Terminating.")
                clientSocket.send(encryptor.encrypt("Nonce not OK".encode("ascii")))
            
        message = clientSocket.recv(2048)
        rawMessage = decryptor.decrypt(message)
        sym_key = rawMessage
        cipher = AES.new(sym_key, AES.MODE_ECB)
        message = "OK"
        message = cipher.encrypt(pad(message.encode("ascii"), 16))
        
        
        #send "OK"
        clientSocket.send(message)

        inboxChecked = False
        running = 1
        while running:
            
            #recieve menu
            message = clientSocket.recv(2048)
            message = unpad(cipher.decrypt(message), 16).decode("ascii")
            print(message, end = " ")
            choice = input()

            validChoices = [1, 2, 3, 4]
            while choice in validChoices:
                choice = input("Invalid choice. Enter a choice between 1 and 4: ")
            
            #send choice
            message = cipher.encrypt(pad(choice.encode("ascii"), 16))
            clientSocket.send(message)

            #send e-mail
            if choice == "1":
                
                emailConfirm = clientSocket.recv(2048)
                emailConfirm = unpad(cipher.decrypt(emailConfirm), 16).decode("ascii")
                
                if emailConfirm == "Send the email":
                    emailMessage, contentLength, titleLength = messageBuild(uName)
                    if (contentLength == False) or (titleLength == False):
                        errorMessage = cipher.encrypt(pad("Error".encode("ascii"), 16))
                        clientSocket.send(errorMessage)
                        continue
                    emailCrypt = cipher.encrypt(pad(emailMessage.encode("ascii"), 16))
                    clientSocket.send(emailCrypt)
                    emailUncrypt = unpad(cipher.decrypt(emailCrypt), 16).decode("ascii")

                    print("The message is sent to the server")
            
            #view inbox
            elif choice == "2":
                inboxChecked = True
                inbox = clientSocket.recv(2048)
                inbox = unpad(cipher.decrypt(inbox), 16).decode("ascii")
                print(inbox)

            #view email contents
            elif choice == "3":
                emailIndex = clientSocket.recv(2048)
                emailIndex = unpad(cipher.decrypt(emailIndex), 16).decode("ascii")
                #if inbox not checked, then print and send error
                if not inboxChecked:
                    print("\nEmail list has not been recieved, choose option 2 first\n")
                    errorMessage = cipher.encrypt(pad("Error".encode("ascii"), 16))
                    clientSocket.send(errorMessage)  
                    continue                
                #Get desired email
                wantedIndex = input("Enter the email index you wish to view: ")
                wantedEmail = getEmailName(inbox, wantedIndex)
                if wantedEmail == "Error":
                    errorMessage = cipher.encrypt(pad("Error".encode("ascii"), 16))
                    clientSocket.send(errorMessage)
                    continue
                wantedCrypt = cipher.encrypt(pad(wantedEmail.encode("ascii"), 16))
                clientSocket.send(wantedCrypt)
                #Get and print retrieved email
                recievedEmail = clientSocket.recv(2048)
                recievedEmail = unpad(cipher.decrypt(recievedEmail), 16).decode("ascii")    
                print("\n" + recievedEmail + "\n")
            
            #disconnect
            elif choice == "4":
                print("The connection is terminated with the server.")
                running = 0
                clientSocket.close()


    except socket.error as e:
        print("an error occured", e)
        clientSocket.close()
        sys.exit(1)
        
def getEmailName(inbox, index):
    inbox = inbox.split("\n")
    #if index invalid, return an Error to server
    if len(inbox) <= 1 or len(inbox) - 1 <= int(index):
        print("\nInvalid index \n")
        return "Error"
    messageParts = inbox[int(index)].split(" ")
    filteredMessageParts = []
    for part in messageParts:
        if part != "":
            filteredMessageParts.append(part)
            
    if len(filteredMessageParts) > 5:
        title = ""
        for i in range(4,len(filteredMessageParts)):
            title += filteredMessageParts[i] + " "
        title = title.strip(" ")
    else:
        title = filteredMessageParts[4]    
        
    return filteredMessageParts[1] + "_" + title
    
        
def messageBuild(uName):
    titleLength = True
    contentLength = True
    
    emailMessage = ""
    emailDest = input("Enter destinations (seperated by ;): ")
    emailTitle = input("Enter title: ")
    if len(emailTitle) >= 100:
        print("Title is too long. Must be less than 100 characters. Current length is " + str(len(emailTitle)) + ".")
        titleLength = False
        return (emailMessage, contentLength, titleLength)
        
    emailType = input("Would you like to load contents from a file? (Y/N) ")
    emailEntry = ""
    if emailType == "Y":
        fileEntry = input("Enter filename: ")
        f = open(fileEntry, "r")
        emailEntry = f.read()
        
    elif emailType == "N":
        emailEntry = input("Enter message contents: ")
    
    else:
        print("Invalid choice")
    
    if len(emailEntry) >= 1000000:
        print("Content is too long, must be less that 1000000 characters. Current length is " + str(len(emailEntry)) + ".")
        contentLength = False
        return (emailMessage, contentLength, titleLength)
        
    emailMessage = "From: {}\nTo: {}\nTitle: {}\nContent Length: {}\nContent: \n{}".format(uName, emailDest, emailTitle, len(emailEntry), emailEntry)
    
    return (emailMessage, contentLength, titleLength)
    
    
#--------
client()
