'''
Program creates public and private keys in sub folders for use in
the secure e-mail application.
'''

from Crypto.PublicKey import RSA  

def clientKeys(keys):
    '''
    Function takes an iterable with a list of clients
    and creates asymetric keys in a folder called clients with the
    names of the given iterable.

    Paras - Keys - Iter - List of clients.
    return - None
    '''
    key = RSA.generate(2048)
    private_key = key.export_key()
    for item in keys:
        file_out = open(f"client/{item}_private.pem", "wb")
        file_out.write(private_key)
        file_out.close()

    public_key = key.publickey().export_key()
    for item in keys:
        file_out = open(f"client/{item}_public.pem", "wb")
        file_out.write(public_key)
        file_out = open(f"server/{item}_public.pem", "wb")
        file_out.write(public_key)
        file_out.close()

def serverKeys():
    '''
    Function creates asymetric server keys for the 
    email application.

    Params - None
    Return - None
    '''
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open("server/server_private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open("server/server_public.pem", "wb")
    file_out.write(public_key)
    file_out = open("client/server_public.pem", "wb")
    file_out.write(public_key)
    file_out.close()


def main():
    
    keys = ["client1", "client2", "client3", "client4", "client5"]
    clientKeys(keys)
    serverKeys()

main()