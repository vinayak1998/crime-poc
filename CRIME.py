import binascii
import sys
import re
import random
import string
import zlib
import hmac, hashlib, base64
from Crypto.Cipher import AES
from Crypto import Random


# generates random IV and Key  for the AES cypher
def read_IV_and_KEY():
    IV = Random.new().read( AES.block_size )
    KEY = Random.new().read( AES.block_size )
    return IV,KEY

# As we are using AES, we need a padding of 16 blocks n any given input s and this returns the padding
def pad(s):
    return (16 - len(s) % 16) * chr((16 - len(s) - 1) % 16)

"""encrypt here kes the message,
first encodes it, then comrpesses it with zlib (example DEFLATE shown in report)
then the compressed message is padded with the above function. 
Then the new raw data is constructed which is returned which is basically 
combination of compressed data along with it's oading, which is then
ecypted with AES and returend but the funtion.
"""
def encrypt( msg):
    cipher = AES.new(KEY, AES.MODE_CBC, IV )
    return cipher.encrypt(zlib.compress(msg.encode()) + pad(zlib.compress(msg.encode())).encode())

#basic request used in adjust padding
def basic_payload(garb,found,string,secret):
    return (garb + "flag=" + ''.join(found) + string + ' ' + secret)

def find_recursive(found,p):
    temp = []
    for i in range(33,127):

        #sends first request
        enc1 = encrypt(GARB + "flag=" + ''.join(found) + chr(i) + '~#:/[|/ç' + ' ' + SECRET) #the join.found method i used for leveragin already
        #sends second request with inverted payload
        enc2 = encrypt(GARB + "flag=" + '~#:/[|/ç' + ''.join(found) + chr(i) + ' ' + SECRET)
        
        #if the length of the payload is smaller that means charaacter is confirmed
        if len(enc1) < len(enc2):
            temp.append(chr(i)) #hence appended


    for i in range(0, len(temp)):
        t = list(found)
        t.append(temp[i])
        sys.stdout.write('\r flag=%s' % ''.join(t))
        p = find_recursive(t,p)

    if len(temp) == 0:
        p += 1
        print("")
    return p    


#padding is adjusted so that we can have a padding of length 1
def adjust_padding():
    garbage = ''
    found = []
    l = 0 
    origin = encrypt(basic_payload(garbage,found,'~#:/[|/ç',SECRET))
    while True:  
        enc = encrypt(basic_payload(garbage,found,'~#:/[|/ç',SECRET))
        if len(enc) > len(origin):
            break
        else:
            l += 1
            garbage = ''.join(random.sample(string.ascii_lowercase + string.digits, k=l)) #length of padding is 1
    return garbage[:-1]

#runs the recursive tree function.
def run():
    found = []
    p = find_recursive(found, 0)
    print("\nFound", str(p), "possibilities of the secret cookie! :D")
    return



if __name__ == '__main__':

    print("CRIME Proof of Concept (using a recursive two_tries method) - Vinayak Rastogi (2016CS10345)\n")
    IV,KEY = read_IV_and_KEY()  #randomly generated IV and KEY
    sec = input("Enter your own secret cookie (WITHOUT SPACES): ")  
    SECRET = "flag={"+ sec +"}"
    #SECRET = "flag={i_love_this_assignment_very_informative}"
    print("Secret TOKEN :", SECRET)
    print("Encrypted with: [33mAES-256-CBC]")
    print("")
    GARB = adjust_padding()
    print("")
    run()
    print("")