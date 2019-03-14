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

    #Read from File
    f = open("ctext.txt", "rb")
    ciphertext = f.read()
    f.close()

    #decrypt
    k = open("key.txt", "rb")
    key = k.read()
    k.close()
    i = open("iv.txt", "rb")
    iv = i.read()
    i.close()
    obj2 = AES.new(key, AES.MODE_CBC,iv)
    message = obj2.decrypt(ciphertext)
    message = message.rstrip()

    #print
    print("The recieved ciphertext: " + str(ciphertext))
    print("From Alice: " + message)
 
if partSelect == '2':
    ################################ Part Two ################################

    print("******* You are now testing Part Two *******")
    print('')

    #Generate RSA KeyPair - private and public 
    key2 = RSA.generate(2048)

    private_key = key2.export_key()
    f = open("BobPrivate.pem", "wb")
    f.write(private_key)
    f.close()

    public_key = key2.publickey().export_key()
    f = open ("BobPublic.pem", "wb")
    f.write(public_key)
    f.close()

    #Get message
    message2 = raw_input("What would you like to encrypt with RSA: ")
    print('')
    
    #encrypt
    pubk = RSA.importKey(open('BobPublic.pem').read())
    cipher = PKCS1_OAEP.new(pubk)
    enc_data = cipher.encrypt(message2)

    #Write
    f = open("ctext.txt", "wb")
    f.write(enc_data)
    f.close()

    #Get Message
    f = open("ctext.txt", "rb")
    encData = f.read()
    f.close()
    
    #Decrypt
    privk = RSA.import_key(open('BobPrivate.pem').read())
    cipher2 = PKCS1_OAEP.new(privk)
    dec_message = cipher2.decrypt(encData)

    #print
    print('')
    print("The origional plaintext is: " + message2)
    print("The encrypted message is: " )
    print(str(enc_data))
    print("The recieved encrypted message is: " )
    print(str(encData))
    print("The decoded message is: " + dec_message)
    print('')

if partSelect == '3':
    ################################ Part Three ################################

    print("******* There is no Part 3 here *******")
    print('')

if partSelect == '4':
    ################################ Part Four ################################

    print("******* You are now testing Part Four *******")
    ('')

    #read key
    f = open("pt4key.txt", "rb")
    HMACKey = f.read()
    f.close()

    #read message and HMAC
    f = open("mactext.txt", "rb")
    mac = f.readline()
    mac = mac.strip('\n')
    mac = mac.rstrip()
    msg = f.readline()  
    print("The recieved HMAC is: " + mac)
    print("The recieved message is: " + msg)
    #verify MAC and print
    h = HMAC.new(HMACKey, digestmod=SHA256)
    h.update(msg)

    try:
        h.hexverify(mac)
        print("The message '%s' is authentic" % msg)
    except ValueError:
        print("The message or the key is wrong.")

    print('')

if partSelect == '5':
    ################################ Part Five ################################

    print("******* You are now testing Part Five *******")
    print('')

    #Get message and signature
    f = open("sigtext.txt", "rb")
    sig = f.read()
    f.close()

    f = open("text.txt", "rb")
    msg2 = f.read()  
    f.close()

    print("The recieved sig is: " + str(sig))
    print("The recieved message is: " + msg2)

    #Get public key
    Apubk = RSA.importKey(open('AlicePublic.der').read())

    #verify
    h = SHA256.new(msg2)
    try:
        pkcs1_15.new(Apubk).verify(h, sig)
        print("The signature is valid.")
    except(ValueError, TypeError):
        print("The signature is not valid.")

if partSelect == '6':
    ################################ Part Six ################################

    print("******* You are now testing Part six *******")
    print('')

    #Get Message
    message6 = raw_input("What would you like to time: ")
    print('')

    #HMAC Time

    HMACStartTime = time.time()

    for x in range(100):
        messageTemp = message6
        
        #Get key
        f = open("pt4key.txt", "rb")
        HMACKey = f.read()
        f.close()

        #Generate HMAC using key
        h = HMAC.new(HMACKey, digestmod=SHA256)
        h.update(messageTemp)

    HMACEndTime = time.time()

    HMACTotalTime = HMACEndTime - HMACStartTime

    HMACAveageTime = HMACTotalTime / 100

    genTimeTotal = 0
    verTimeTotal = 0

    #SIG 
    for x in range(100):
        messageTemp2 = message6

        genTimeStart = time.time()
        #Use Private to compute signature
        key7 = RSA.import_key(open('BobPrivate.pem').read())
        h = SHA256.new(messageTemp2)
        signature = pkcs1_15.new(key7).sign(h)
        genTimeEnd = time.time()

        genTimeTotal = genTimeTotal + (genTimeEnd - genTimeStart)

        #Verify
        verTimeStart = time.time()
        #Get public key
        pubk = RSA.importKey(open('BobPublic.pem').read())

        #verify
        h = SHA256.new(messageTemp2)
        try:
            pkcs1_15.new(pubk).verify(h, signature)
        except(ValueError, TypeError):
            print("This shouldnt hit")
        verTimeEnd = time.time()
        verTimeTotal = verTimeTotal + (verTimeEnd - verTimeStart)

    genAverageTime = genTimeTotal / 100
    verAverageTime = verTimeTotal / 100
    print("The average HMAC time: " + str(HMACAveageTime))
    print("The average signing time: " + str(genAverageTime))
    print("The average verification time: " + str(verAverageTime))



