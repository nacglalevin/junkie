import sys
import hashlib
import hmac
import base64
import json
import argparse
import datetime
from collections import OrderedDict
try:
    from Cryptodome.Signature import PKCS1_v1_5, DSS, pss
    from Cryptodome.Hash import SHA256, SHA384, SHA512
    from Cryptodome.PublicKey import RSA, ECC
except:
    print("WARNING: Cryptodome libraries not imported - these are needed for asymmetric crypto signing and verifying")
    print("On most Linux systems you can run the following command to install:")
    print("pip3 install pycryptodomex\n")

def checkSig(sig, contents, key):
    quiet = False
    if key == "":
        print("Type in the key to test")
        key = input("> ")
    testKey(key.encode(), sig, contents, headDict, quiet)

def checkSigKid(sig, contents):
    quiet = False
    print("\nLoading key file...")
    try:
        key1 = open(keyFile).read()
        print("File loaded: "+keyFile)
        testKey(key1.encode(), sig, contents, headDict, quiet)
    except:
        print("Could not load key file")
        exit(1)

def crackSig(sig, contents):
    quiet = True
    if headDict["alg"][0:2] != "HS":
        print("Algorithm is not HMAC-SHA - cannot test against passwords, try the Verify function.")
        return
    print("\nLoading key dictionary...")
    try:
        print("File loaded: "+keyList)
        keyLst = open(keyList, "r", encoding='utf-8', errors='ignore')
        nextKey = keyLst.readline()
    except:
        print("No dictionary file loaded")
        exit(1)
    print("Testing passwords in dictionary...")
    utf8errors = 0
    wordcount = 0
    while nextKey:
        wordcount += 1
        try:
            cracked = testKey(nextKey.strip().encode('UTF-8'), sig, contents, headDict, quiet)
        except:
            cracked = False
        if not cracked:
            if wordcount % 1000000 == 0:
                print("[*] Tested "+str(int(wordcount/1000000))+" million passwords so far")
            try:
                nextKey = keyLst.readline()
            except:
                utf8errors  += 1
                nextKey = keyLst.readline()
        else:
            return
    if cracked == False:
        print("\n[-] Key not in dictionary")
        print("\n===============================\nAs your list wasn't able to crack this token you might be better off using longer dictionaries, custom dictionaries, mangling rules, or brute force attacks.\nhashcat (https://hashcat.net/hashcat/) is ideal for this as it is highly optimised for speed. Just add your JWT to a text file, then use the following syntax to give you a good start:\n\n[*] dictionary attacks: hashcat -a 0 -m 16500 jwt.txt passlist.txt\n[*] rule-based attack:  hashcat -a 0 -m 16500 jwt.txt passlist.txt -r rules/best64.rule\n[*] brute-force attack: hashcat -a 3 -m 16500 jwt.txt ?u?l?l?l?l?l?l?l -i --increment-min=6\n===============================\n")
    if utf8errors > 0:
        print(utf8errors, " UTF-8 incompatible passwords skipped")

def testKey(key, sig, contents, headDict, quiet):
    if headDict["alg"] == "HS256":
        testSig = base64.urlsafe_b64encode(hmac.new(key,contents,hashlib.sha256).digest()).decode('UTF-8').strip("=")
    elif headDict["alg"] == "HS384":
        testSig = base64.urlsafe_b64encode(hmac.new(key,contents,hashlib.sha384).digest()).decode('UTF-8').strip("=")
    elif headDict["alg"] == "HS512":
        testSig = base64.urlsafe_b64encode(hmac.new(key,contents,hashlib.sha512).digest()).decode('UTF-8').strip("=")
    else:
        print("Algorithm is not HMAC-SHA - cannot test with this tool.")
        exit(1)
    if testSig == sig:
        cracked = True
        if len(key) > 25:
            print("\n[+] "+key[0:25].decode('UTF-8')+"...(output trimmed) is the CORRECT key!")
        else:
            print("\n[+] "+key.decode('UTF-8')+" is the CORRECT key!")
        return cracked
    else:
        cracked = False
        if quiet == False:
            if len(key) > 25:
                print("[-] "+key[0:25].decode('UTF-8')+"...(output trimmed) is not the correct key")
            else:
                print("[-] "+key.decode('UTF-8')+" is not the correct key")
        return cracked

def buildHead(alg, headDict):
    newHead = headDict
    newHead["alg"] = alg
    newHead = base64.urlsafe_b64encode(json.dumps(newHead,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    return newHead

def newRSAKeyPair():
    new_key = RSA.generate(2048, e=65537)
    pubKey = new_key.publickey().exportKey("PEM")
    privKey = new_key.exportKey("PEM")
    return pubKey, privKey

def newECKeyPair():
    new_key = ECC.generate(curve='P-256')
    pubKey = new_key.public_key().export_key(format="PEM")
    privKey = new_key.export_key(format="PEM")
    return pubKey, privKey

def signToken(headDict, paylDict, key, keyLength):
    newHead = headDict
    newHead["alg"] = "HS"+str(keyLength)
    if keyLength == 384:
        newContents = base64.urlsafe_b64encode(json.dumps(newHead,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
        newSig = base64.urlsafe_b64encode(hmac.new(key.encode(),newContents.encode(),hashlib.sha384).digest()).decode('UTF-8').strip("=")
        badSig = base64.b64encode(hmac.new(key.encode(),newContents.encode(),hashlib.sha384).digest()).decode('UTF-8').strip("=")
    elif keyLength == 512:
        newContents = base64.urlsafe_b64encode(json.dumps(newHead,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
        newSig = base64.urlsafe_b64encode(hmac.new(key.encode(),newContents.encode(),hashlib.sha512).digest()).decode('UTF-8').strip("=")
        badSig = base64.b64encode(hmac.new(key.encode(),newContents.encode(),hashlib.sha512).digest()).decode('UTF-8').strip("=")
    else:
        newContents = base64.urlsafe_b64encode(json.dumps(newHead,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
        newSig = base64.urlsafe_b64encode(hmac.new(key.encode(),newContents.encode(),hashlib.sha256).digest()).decode('UTF-8').strip("=")
        badSig = base64.b64encode(hmac.new(key.encode(),newContents.encode(),hashlib.sha256).digest()).decode('UTF-8').strip("=")
    return newSig, badSig, newContents

def jwksGen(headDict, paylDict, jku, privateKey, kid="jwt_tool"):
    newHead = headDict
    nowtime = str(int(datetime.datetime.now().timestamp()))
    if privateKey:
        key = RSA.importKey(open(privateKey).read())
        pubKey = key.publickey().exportKey("PEM")
        privKey = key.export_key(format="PEM")
        new_key = RSA.importKey(pubKey)
        n = base64.urlsafe_b64encode(new_key.n.to_bytes(256, byteorder='big'))
        e = base64.urlsafe_b64encode(new_key.e.to_bytes(3, byteorder='big'))
        privKeyName = privateKey
    else:
        pubKey, privKey = newRSAKeyPair()
        new_key = RSA.importKey(pubKey)
        n = base64.urlsafe_b64encode(new_key.n.to_bytes(256, byteorder='big'))
        e = base64.urlsafe_b64encode(new_key.e.to_bytes(3, byteorder='big'))
        privKeyName = "private_jwttool_RSA_"+nowtime+".pem"
        with open(privKeyName, 'w') as test_priv_out:
            test_priv_out.write(privKey.decode())
    newjwks = {}
    newjwks["kty"] = "RSA"
    newjwks["kid"] = kid
    newjwks["use"] = "sig"
    newjwks["e"] = str(e.decode('UTF-8'))
    newjwks["n"] = str(n.decode('UTF-8').rstrip("="))
    newHead["jku"] = jku
    newHead["alg"] = "RS256"
    key = RSA.importKey(privKey)
    newContents = base64.urlsafe_b64encode(json.dumps(newHead,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    newContents = newContents.encode('UTF-8')
    h = SHA256.new(newContents)
    signer = PKCS1_v1_5.new(key)
    try:
        signature = signer.sign(h)
    except:
        print("Invalid Private Key")
        exit(1)
    newSig = base64.urlsafe_b64encode(signature).decode('UTF-8').strip("=")
    badSig = base64.b64encode(signature).decode('UTF-8').strip("=")
    jwksout = json.dumps(newjwks,separators=(",",":"), indent=4)
    jwksName = "jwks_jwttool_RSA_"+nowtime+".json"
    with open(jwksName, 'w') as test_jwks_out:
            test_jwks_out.write(jwksout)
    return newSig, badSig, newContents.decode('UTF-8'), jwksout, privKeyName, jwksName

def jwksEmbed(headDict, paylDict):
    newHead = headDict
    pubKey, privKey = newRSAKeyPair()
    new_key = RSA.importKey(pubKey)
    n = base64.urlsafe_b64encode(new_key.n.to_bytes(256, byteorder='big'))
    e = base64.urlsafe_b64encode(new_key.e.to_bytes(3, byteorder='big'))
    jwkbuild = {}
    jwkbuild["kty"] = "RSA"
    jwkbuild["kid"] = "jwt_tool"
    jwkbuild["use"] = "sig"
    jwkbuild["e"] = str(e.decode('UTF-8'))
    jwkbuild["n"] = str(n.decode('UTF-8').rstrip("="))
    newHead["jwk"] = jwkbuild
    newHead["alg"] = "RS256"
    key = RSA.importKey(privKey)
    newContents = base64.urlsafe_b64encode(json.dumps(newHead,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    newContents = newContents.encode('UTF-8')
    h = SHA256.new(newContents)
    signer = PKCS1_v1_5.new(key)
    try:
        signature = signer.sign(h)
    except:
        print("Invalid Private Key")
        exit(1)
    newSig = base64.urlsafe_b64encode(signature).decode('UTF-8').strip("=")
    badSig = base64.b64encode(signature).decode('UTF-8').strip("=")
    return newSig, badSig, newContents.decode('UTF-8')

def signTokenRSA(headDict, paylDict, privKey, keyLength):
    newHead = headDict
    newHead["alg"] = "RS"+str(keyLength)
    key = RSA.importKey(open(privKey).read())
    newContents = base64.urlsafe_b64encode(json.dumps(newHead,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    newContents = newContents.encode('UTF-8')
    if keyLength == 256:
        h = SHA256.new(newContents)
    elif keyLength == 384:
        h = SHA384.new(newContents)
    elif keyLength == 512:
        h = SHA512.new(newContents)
    else:
        print("Invalid RSA key length")
        exit(1)
    signer = PKCS1_v1_5.new(key)
    try:
        signature = signer.sign(h)
    except:
        print("Invalid Private Key")
        exit(1)
    newSig = base64.urlsafe_b64encode(signature).decode('UTF-8').strip("=")
    badSig = base64.b64encode(signature).decode('UTF-8').strip("=")
    return newSig, badSig, newContents.decode('UTF-8')

def signTokenEC(headDict, paylDict, privKey, keyLength):
    newHead = headDict
    newHead["alg"] = "ES"+str(keyLength)
    key = ECC.import_key(open(privKey).read())
    newContents = base64.urlsafe_b64encode(json.dumps(newHead,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    newContents = newContents.encode('UTF-8')
    if keyLength == 256:
        h = SHA256.new(newContents)
    elif keyLength == 384:
        h = SHA384.new(newContents)
    elif keyLength == 512:
        h = SHA512.new(newContents)
    else:
        print("Invalid RSA key length")
        exit(1)
    signer = DSS.new(key, 'fips-186-3')
    try:
        signature = signer.sign(h)
    except:
        print("Invalid Private Key")
        exit(1)
    newSig = base64.urlsafe_b64encode(signature).decode('UTF-8').strip("=")
    badSig = base64.b64encode(signature).decode('UTF-8').strip("=")
    return newSig, badSig, newContents.decode('UTF-8')

def signTokenPSS(headDict, paylDict, privKey, keyLength):
    newHead = headDict
    newHead["alg"] = "PS"+str(keyLength)
    key = RSA.importKey(open(privKey).read())
    newContents = base64.urlsafe_b64encode(json.dumps(newHead,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    newContents = newContents.encode('UTF-8')
    if keyLength == 256:
        h = SHA256.new(newContents)
    elif keyLength == 384:
        h = SHA384.new(newContents)
    elif keyLength == 512:
        h = SHA512.new(newContents)
    else:
        print("Invalid RSA key length")
        exit(1)
    try:
        signature = pss.new(key).sign(h)
    except:
        print("Invalid Private Key")
        exit(1)
    newSig = base64.urlsafe_b64encode(signature).decode('UTF-8').strip("=")
    badSig = base64.b64encode(signature).decode('UTF-8').strip("=")
    return newSig, badSig, newContents.decode('UTF-8')

def verifyTokenRSA(headDict, paylDict, sig, pubKey):
    key = RSA.importKey(open(pubKey).read())
    newContents = base64.urlsafe_b64encode(json.dumps(headDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    newContents = newContents.encode('UTF-8')
    if "-" in sig:
        try:
            sig = base64.urlsafe_b64decode(sig)
        except:
            pass
        try:
            sig = base64.urlsafe_b64decode(sig+"=")
        except:
            pass
        try:
            sig = base64.urlsafe_b64decode(sig+"==")
        except:
            pass
    elif "+" in sig:
        try:
            sig = base64.b64decode(sig)
        except:
            pass
        try:
            sig = base64.b64decode(sig+"=")
        except:
            pass
        try:
            sig = base64.b64decode(sig+"==")
        except:
            pass
    else:
        print("Signature not Base64 encoded HEX")
    if headDict['alg'] == "RS256":
        h = SHA256.new(newContents)
    elif headDict['alg'] == "RS384":
        h = SHA384.new(newContents)
    elif headDict['alg'] == "RS512":
        h = SHA512.new(newContents)
    else:
        print("Invalid RSA algorithm")
    verifier = PKCS1_v1_5.new(key)
    try:
        valid = verifier.verify(h, sig)
        if valid:
            print("RSA Signature is VALID")
            valid = True
        else:
            print("RSA Signature is INVALID")
            valid = False
    except:
        print("The Public Key is invalid")
    return valid

def verifyTokenEC(headDict, paylDict, sig, pubKey):
    newContents = base64.urlsafe_b64encode(json.dumps(headDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    message = newContents.encode('UTF-8')
    if "-" in str(sig):
        try:
            signature = base64.urlsafe_b64decode(sig)
        except:
            pass
        try:
            signature = base64.urlsafe_b64decode(sig+"=")
        except:
            pass
        try:
            signature = base64.urlsafe_b64decode(sig+"==")
        except:
            pass
    elif "+" in str(sig):
        try:
            signature = base64.b64decode(sig)
        except:
            pass
        try:
            signature = base64.b64decode(sig+"=")
        except:
            pass
        try:
            signature = base64.b64decode(sig+"==")
        except:
            pass
    else:
        print("Signature not Base64 encoded HEX")
    if headDict['alg'] == "ES256":
        h = SHA256.new(message)
    elif headDict['alg'] == "ES384":
        h = SHA384.new(message)
    elif headDict['alg'] == "ES512":
        h = SHA512.new(message)
    else:
        print("Invalid ECDSA algorithm")
    pubKey = open(pubKey, "r")
    pub_key = ECC.import_key(pubKey.read())
    verifier = DSS.new(pub_key, 'fips-186-3')
    try:
        verifier.verify(h, signature)
        print("ECC Signature is VALID")
        valid = True
    except:
        print("ECC Signature is INVALID")
        valid = False
    return valid

def verifyTokenPSS(headDict, paylDict, sig, pubKey):
    key = RSA.importKey(open(pubKey).read())
    newContents = base64.urlsafe_b64encode(json.dumps(headDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    newContents = newContents.encode('UTF-8')
    if "-" in sig:
        try:
            sig = base64.urlsafe_b64decode(sig)
        except:
            pass
        try:
            sig = base64.urlsafe_b64decode(sig+"=")
        except:
            pass
        try:
            sig = base64.urlsafe_b64decode(sig+"==")
        except:
            pass
    elif "+" in sig:
        try:
            sig = base64.b64decode(sig)
        except:
            pass
        try:
            sig = base64.b64decode(sig+"=")
        except:
            pass
        try:
            sig = base64.b64decode(sig+"==")
        except:
            pass
    else:
        print("Signature not Base64 encoded HEX")
    if headDict['alg'] == "PS256":
        h = SHA256.new(newContents)
    elif headDict['alg'] == "PS384":
        h = SHA384.new(newContents)
    elif headDict['alg'] == "PS512":
        h = SHA512.new(newContents)
    else:
        print("Invalid RSA algorithm")
    verifier = pss.new(key)
    try:
        valid = verifier.verify(h, sig)
        print("RSA-PSS Signature is VALID")
        valid = True
    except:
        print("RSA-PSS Signature is INVALID")
        valid = False
    return valid

def parseJWKS(jwksfile):
    jwks = open(jwksfile, "r").read()
    jwksDict = json.loads(jwks, object_pairs_hook=OrderedDict)
    nowtime = int(datetime.datetime.now().timestamp())
    print("JWKS Contents:")
    try:
        keyLen = len(jwksDict["keys"])
        print("Number of keys: "+str(keyLen))
        i = -1
        for jkey in range(0,keyLen):
            i += 1
            print("\n--------")
            try:
                print("Key "+str(i+1))
                kid = str(jwksDict["keys"][i]["kid"])
                print("kid: "+kid)
            except:
                kid = i
                print("Key "+str(i+1))
            for keyVal in jwksDict["keys"][i].items():
                keyVal = keyVal[0]
                print("[+] "+keyVal+" = "+str(jwksDict["keys"][i][keyVal]))
            try:
                x = str(jwksDict["keys"][i]["x"])
                y = str(jwksDict["keys"][i]["y"])
                print("\nFound ECC key factors, generating a public key")
                pubKeyName = genECPubFromJWKS(x, y, kid, nowtime)
                print("[+] "+pubKeyName)
                print("\nAttempting to verify token using "+pubKeyName)
                valid = verifyTokenEC(headDict, paylDict, sig, pubKeyName)
            except:
                pass
            try:
                n = str(jwksDict["keys"][i]["n"])
                e = str(jwksDict["keys"][i]["e"])
                print("\nFound RSA key factors, generating a public key")
                pubKeyName = genRSAPubFromJWKS(n, e, kid, nowtime)
                print("[+] "+pubKeyName)
                print("\nAttempting to verify token using "+pubKeyName)
                valid = verifyTokenRSA(headDict, paylDict, sig, pubKeyName)
            except:
                pass
    except:
        print("Single key file")
        for jkey in jwksDict:
            print("[+] "+jkey+" = "+str(jwksDict[jkey]))
        try:
            kid = 1
            x = str(jwksDict["x"])
            y = str(jwksDict["y"])
            print("\nFound ECC key factors, generating a public key")
            pubKeyName = genECPubFromJWKS(x, y, kid, nowtime)
            print("[+] "+pubKeyName)
            print("\nAttempting to verify token using "+pubKeyName)
            valid = verifyTokenEC(headDict, paylDict, sig, pubKeyName)