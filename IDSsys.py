#!/usr/bin/env python3
import nstp_v2_pb2
import sys
import socket
import struct
import copy

p = sys.argv[0]
sockFile = sys.argv[1]
openConnections = {}
IPtoConnections = {}
blacklist = {}


# Ensure that it doesn't violate the NSTPv2 specification
def spec(msg):
    global openConnections
    global IPtoConnections
    global blacklist
    e = msg.event
    connection = (e.address_family, e.server_address, e.server_port, e.remote_address, e.remote_port)
    if e.remote_address in blacklist.keys():
        print("Blacklisted and trying to create a connection")
        return False

    if e.HasField("connection_established"):
        if connection in openConnections.keys():
            print("Failed: Connection already open")
            return False
        else:
            openConnections[connection] = 0
        if e.remote_address in IPtoConnections.keys():
            print("Incrememnting connections")
            IPtoConnections[e.remote_address] += 1
        else:
            print("Starting to increment connections")
            IPtoConnections[e.remote_address] = 1

    elif e.HasField("client_hello"):
        if msg.event.client_hello.major_version != 2:
            print("Failed: Bad Major")
            return False
        if connection not in openConnections.keys():
            print("Failed: hasn't established a connection")
            return False
        elif connection in openConnections.keys() and openConnections[connection] == 1:
            print("Failed: Connection already open")
            return False
        else:
            # OpenConnections change to 1 once a client hello has been sent
            openConnections[connection] = 1
    elif (e.HasField("load_request") or e.HasField("store_request") or e.HasField("ping_request")) and (connection not in openConnections.keys() or openConnections[connection] == 0):
        print("Haven't established a connection")
        return False
    elif e.HasField("connection_terminated"):
        if connection not in openConnections.keys():
            print("Haven't established a connection")
            return False
        print("Terminated Connection")
        del openConnections[connection]
        IPtoConnections[e.remote_address] -= 1
        return True
    return True

def checkPath(path):
    if "/" not in path.key and ".." not in path.key:
        return True
    if path.key[0] == "/" or path.key[0:2] == "..":
        return False
    else:
        pieces = path.key.split("/")
        print(pieces)
        stack = []
        for i in pieces:
            if ".." not in i:
                stack.append(i)
            else:
                if len(stack) == 0:
                    return False
                else:
                    stack.pop()
        return len(stack) >= 0

# NSTP-SEC-2020-0001
def sanitize(msg):
    print("Sanitizing")
    if msg.event.HasField("load_request"):
        print("Analyzing Load request")
        if not checkPath(msg.event.load_request):
            return False
    elif msg.event.HasField("store_request"):
        print("Analyzing store request")
        if not checkPath(msg.event.store_request):
            return False
    return True

# NSTP-SEC-2020-0002
def bufferOverflowCheck(msg):
    print("Checking buffer overflow")
    storeReq = msg.event.store_request
    if storeReq != 0:
        if len(storeReq.key) > 512:
            print("Failed: store request")
            return False
    return True

def terminate_connection_tuple(pairs, s):
    response = nstp_v2_pb2.IDSMessage()
    terminate = nstp_v2_pb2.IDSTerminateConnection()
    terminate.address_family = pairs[0]
    terminate.server_address = pairs[1]
    terminate.server_port = pairs[2]
    terminate.remote_address = pairs[3]
    terminate.remote_port = pairs[4]

    response.terminate_connection.address_family = terminate.address_family
    response.terminate_connection.server_address = terminate.server_address
    response.terminate_connection.server_port = terminate.server_port
    response.terminate_connection.remote_address = terminate.remote_address
    response.terminate_connection.remote_port = terminate.remote_port

    print("RESPONSE FOR TERMINATE ", response)
    sentMsg = response.SerializeToString()
    sentLen = struct.pack("!H", len(sentMsg))
    s.sendall(sentLen + sentMsg)

def removeConnections(ip, s):
    val = False
    conns = copy.deepcopy(openConnections).keys()
    for i in conns:
        if i[3] == ip:
            print("Removing connection")
            del openConnections[i]
            terminate_connection_tuple(i, s)
            val = True
    return val

def maxSingleIPConnections(msg, s):
    global openConnections
    global IPtoConnections
    global blacklist
    highestConn = 0
    highestIP = None
    for i in IPtoConnections.keys():
        if IPtoConnections[i] > highestConn:
            highestConn = IPtoConnections[i]
            highestIP = i
    blacklist[highestIP] = 0
    removeConnections(highestIP, s)

#NSTP-SEC-2020-0003
def maxConcurrency(msg, s):
    global openConnections
    global blacklist
    print("OPEN CONNECTIONS", len(openConnections))
    if len(openConnections.keys()) > 500:
        print("TOO MANY OPEN CONNECTIONS")
        maxSingleIPConnections(msg, s)

    if msg.event.remote_address in blacklist.keys():
        return False
    else:
        return True

def recv_all(s,n):
    xs = b""
    while len(xs) < n:
        x = s.recv(n-len(xs))
        if len(x) == 0:
            break
        xs += x
    return xs


def main():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sockFile)
    s.settimeout(10)

    while True:
        try:
            # Recieve Message
            #msg = s.recv(2048)
            lengthInBytes = recv_all(s, 2)
            if len(lengthInBytes) == 0:
                s.close()
                return 0
            #length = struct.unpack("!H", msg[0:2])[0]
            length = struct.unpack("!H", lengthInBytes)[0]
            print(length)
            #msg = msg[2:]
            msg = recv_all(s, length)
            read = nstp_v2_pb2.IDSMessage()
            read.ParseFromString(msg)
            print ("MSG: ", read)

            # Formulate Response
            response = nstp_v2_pb2.IDSMessage()
            dec = nstp_v2_pb2.IDSDecision()
            dec.event_id = read.event.event_id

            #Check for Sec1/Sec2 Advisory/ Spec
            dec.allow = sanitize(read) and spec(read) and bufferOverflowCheck(read)
            response.decision.event_id = dec.event_id
            response.decision.allow = dec.allow

            # Check if at Sec3 --> Terminate connection
            skip = False
            if not maxConcurrency(read, s):
                response.decision.allow = False
                skip = True
            
            # Blacklist client if False
            if response.decision.allow == False:
                ip = read.event.remote_address
                blacklist[ip] = 0
                if removeConnections(ip, s) or skip:
                    continue

            # Send Message back prefixed with length 
            sentMsg = response.SerializeToString()
            sentLen = struct.pack("!H", len(sentMsg))
            s.sendall(sentLen + sentMsg)
            print("IDS RESPONSE: ", response)
        except socket.timeout:
            break
    s.close()
    return 0

main()
