from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util import Padding
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
import time
from Crypto.Signature import pkcs1_15
partSelect = raw_input("What part would you like to test: ")
print('')

if partSelect == '1':
    ################################ Part One ################################

    print("******* You are now testing Part One *******")
    print('')
    #Get message
    message = raw_input("What would you like to send to Bob: ")
    print('')

    #Add Padding
    byteMessage = message.encode('utf-8')
    paddedMessage = Padding.pad(byteMessage, 32, style='pkcs7')

    #encryption
    k = open("key.txt", "r")
    key = k.read()
    k.close()
    i = open("iv.txt", "r")
    iv = i.read()
    i.close()
    obj = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = obj.encrypt(paddedMessage)

    #Write to file 
    f = open("ctext.txt", "wb")
    f.write(str(ciphertext))
    f.close()

    print('')
    print("The plaintext message: " + message)
    print("The ciphertext: " + str(ciphertext))
    

if partSelect == '2':
    ################################ Part Two ################################

    print("******* There is no part two here *******")
    print('')


if partSelect == '3':
    ################################ Part Three ################################

    print("******* You are now testing Part Three *******")
    print('')
    #Get message
    message = raw_input("Time trial phase: ")
    print('')

    #get key and iv
    k = open("key.txt", "rb")
    keyAES = k.read()
    k.close()

    i = open("iv.txt", "rb")
    iv = i.read()
    i.close()

    #RSA Key Generation
    key2 = RSA.generate(2048)

    private_key = key2.export_key()
    f = open("Private.pem", "w+")
    f.write(private_key)
    f.close()

    public_key = key2.publickey().export_key()
    f = open ("Public.pem", "w+")
    f.write(public_key)
    f.close()

    f = open('Public.pem', 'rb')
    public_key = f.read()
    f.close()

    f = open('Private.pem', 'rb')
    private_key = f.read()
    f.close()

    AESencTotalTime = 0
    AESdecTotalTime = 0
    RSAencTotalTime = 0
    RSAdecTotalTime = 0

    #AES
    for x in range(100):
        encStartTime = time.time()
        #Add Padding
        byteMessage = message.encode('utf-8')
        paddedMessage = Padding.pad(byteMessage, 32, style='pkcs7')

        #encryption
        obj = AES.new(keyAES, AES.MODE_CBC, iv)
        ciphertext = obj.encrypt(paddedMessage)

        encEndTime = time.time()

        decStartTime = time.time()

        #decrypt
        obj2 = AES.new(keyAES, AES.MODE_CBC,iv)
        message2 = obj2.decrypt(ciphertext)

        decEndTime = time.time()

        AESencTotalTime = AESencTotalTime + (encEndTime - encStartTime)
        AESdecTotalTime = AESdecTotalTime + (decEndTime - decStartTime)

    AESencPerTrial = AESencTotalTime / 100
    AESdecPerTrial = AESdecTotalTime / 100
    
    #RSA
    for x in range(100):
        
        encStartTime = time.time()

        #encrypt
        pubk = RSA.importKey(public_key)
        cipher = PKCS1_OAEP.new(pubk)
        enc_data = cipher.encrypt(message)

        encEndTime = time.time()

        decStartTime = time.time()

        #Decrypt
        privk = RSA.importKey(private_key)
        cipher2 = PKCS1_OAEP.new(privk)
        dec_message = cipher2.decrypt(enc_data)

        decEndTime = time.time()

        RSAencTotalTime = RSAencTotalTime + (encEndTime - encStartTime)
        RSAdecTotalTime = RSAdecTotalTime + (decEndTime - decStartTime)

    RSAencPerTrial = RSAencTotalTime / 100
    RSAdecPerTrial = RSAdecTotalTime / 100

    print("AES encrypt time per trial: " + str(AESencPerTrial))
    print("AES decrypt time per trial: " + str(AESdecPerTrial))
    print("RSA encrypt time per trial: " + str(RSAencPerTrial))
    print("RSA decrypt time per trial: " + str(RSAdecPerTrial))
    print('')

if partSelect == '4':
    ################################ Part Four ################################

    print("******* You are now testing Part Four *******")
    print('')

    #Get Message
    message4 = raw_input("What would you like to send to Bob: ")
    print('')

    #Get key
    f = open("pt4key.txt", "rb")
    HMACKey = f.read()
    f.close()

    #Generate HMAC using key
    h = HMAC.new(HMACKey, digestmod=SHA256)
    h.update(message4)
    
    #write HMAC and message to mactext
    f = open("mactext.txt", "wb")
    f.write(h.hexdigest())
    f.write('\n')
    f.write(message4)
    f.close()

    print("The plainatext message: " + message4)
    print("The derived HMAC: " + h.hexdigest())

if partSelect == '5':
    ################################ Part Five ################################

    print("******* You are now testing Part Five *******")
    print('')

    #Get Message
    message5 = raw_input("What would you like to send to Bob: ")
    print('')

    #Generate RSA KeyPair - private and public 
    key6 = RSA.generate(2048)

    private_key = key6.export_key()
    f = open("AlicePrivate.der", "wb")
    f.write(private_key)
    f.close()

    public_key = key6.publickey().export_key()
    f = open ("AlicePublic.der", "wb")
    f.write(public_key)
    f.close()

    #Use Private to compute signature
    key5 = RSA.import_key(open('AlicePrivate.der').read())
    h = SHA256.new(message5)
    signature = pkcs1_15.new(key5).sign(h)

    #write to file
    f = open("sigtext.txt", "wb")
    f.write(signature)
    f.close()

    f = open("text.txt", "wb")
    f.write(message5)
    f.close()

    #print
    print("The plaintext is: " + message5)
    print("The signature is: " + str(signature))

if partSelect == '6':
    ################################ Part Six ################################

    print("******* There is no Part Six here*******")
