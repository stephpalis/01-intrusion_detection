#!/usr/bin/env python3
import nstp_v2_pb2
import sys
import socket
import struct

p = sys.argv[0]
sockFile = sys.argv[1]
openConnections = {}
IPtoConnections = {}
blacklist = {}

# Ensure that it doesn't violate the NSTPv2 specification
def spec(msg):
    print("TESTING SPEC")
    e = msg.event
    connection = (e.address_family, e.server_address, e.server_port, e.remote_address, e.remote_port)
    if "connection_established" in str(e) and e.server_address in blacklist.keys():
        print("Blacklisted and trying to create a connection")
        return False
    elif "client_hello" in str(e):
        if msg.event.client_hello.major_version != 2:
            print("Failed: Bad Major")
            return False
        if connection in openConnections.keys():
            print("Failed: Connection already open")
            return False
        else:
            openConnections[connection] = 0
        if e.server_address in IPtoConnections.keys():
            print("Incrememnting connections")
            IPtoConnections[e.server_address] += 1
        else:
            print("Starting to increment connections")
            IPtoConnections[e.server_address] = 1
    elif ("load_request" in str(e) or "store_request" in str(e) or "ping_request" in str(e)) and connection not in openConnections.keys():
        print("Haven't established a connection")
        return False
    elif "connection_terminated" in str(e):
        print("Terminated Connection")
        del openConnections[e]
        IPtoConnections[e.server_address] -= 1
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
    if "load_request" in str(msg.event):
        print("Analyzing Load request")
        if not checkPath(msg.event.load_request):
            return False
    elif "store_request" in str(msg.event):
        print("Analyzing store request")
        if not checkPath(msg.event.store_request):
            return False
    return True

# NSTP-SEC-2020-0002
def bufferOverflowCheck(msg):
    print("Checking buffer overflow")
    storeReq = msg.event.store_request
    if storeReq != 0:
        print("Checking store request")
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

    sentMsg = response.SerializeToString()
    print("SENT MSG", sentMsg)
    sentLen = struct.pack("!H", len(sentMsg))
    s.send(sentLen + sentMsg)


def maxSingleIPConnections(msg, s):
    ip = msg.event.server_address
    if ip in IPtoConnections and IPtoConnections[ip] > 50:
        blacklist[ip] = 0
        for i in openConnections.keys():
            if i[1] == ip:
                terminate_connection_tuple(i, s)

#NSTP-SEC-2020-0003
# TODO track connections from IP addresses - limit to 50 -- blacklist
def maxConcurrency(msg):
    # TODO too nieve? should be counting open connections?
    if len(openConnections) > 500:
        return False
    else:
        return True

def terminate_connection(msg):
    response = nstp_v2_pb2.IDSMessage()
    terminate = nstp_v2_pb2.IDSTerminateConnection()
    terminate.address_family = msg.event.address_family
    terminate.server_address = msg.event.server_address
    terminate.server_port = msg.event.server_port
    terminate.remote_address = msg.event.remote_address
    terminate.remote_port = msg.event.remote_port

    response.terminate_connection.address_family = terminate.address_family
    response.terminate_connection.server_address = terminate.server_address
    response.terminate_connection.server_port = terminate.server_port
    response.terminate_connection.remote_address = terminate.remote_address
    response.terminate_connection.remote_port = terminate.remote_port
    print("TERMINATE CONNECTION: ", response)
    return response

def main():
    print(sockFile)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sockFile)

    while True:
        print("READING")
        # Recieve Message
        msg = s.recv(2048)
        if len(msg) == 0:
            s.close()
            return 0
        length = struct.unpack("!H", msg[0:2])[0]
        msg = msg[2:]
        read = nstp_v2_pb2.IDSMessage()
        read.ParseFromString(msg)
        print ("MSG: ", read)


        # TODO: DELETE: TESTING ONLY:
        '''storeReq = nstp_v2_pb2.StoreRequest()
        storeReq.key = "hqrogvwirdboqtqansgipuncxjbmbkftocsikkoyhzktucwpgzocgrgleydnstaggkqixzcnjwqrquwltucllhkrozebxrcwlaftghxdzwqsnqbumcappxnyjljpjeoyoivzbjxmaeyxjnatritowwinusoxtktkdrlypyavwltnijkourjaustmwxmwrvzuhfxvemxoxkrmygbvclltodejlbfiksssfftiwvhagwkyuubvuoxvpzgwbmrkjelkosdzzmrxfrrdmhyooeqjgzicjlxjqdvtxzgbkwjwwppylsclhcmrnyxqzlwocsloedbfeqyaobsityxgeopxgghcrozieopogkbiijykqzgavcgxrrefezmfvgmogsqsqxqfqtaqfqhyhtfixjrlekexhtynztextgdfufkbsggxjubtcoivscjdlnixutcwwkzlxcpdddjzyucpiqgtycppkrgtsfixhunzwnapvlvhmtldmigmatskneouvcauv"
        storeReq.value = b'1010'
        oldMsg = read
        read = nstp_v2_pb2.IDSMessage()
        read.event.event_id = oldMsg.event.event_id
        read.event.timestamp = oldMsg.event.event_id
        read.event.address_family = oldMsg.event.event_id
        read.event.server_address = oldMsg.event.server_address
        read.event.server_port = oldMsg.event.server_port
        read.event.remote_address = oldMsg.event.remote_address
        read.event.remote_port = oldMsg.event.remote_port

        # Buffer Overflow
        #read.event.store_request.key = storeReq.key
        #read.event.store_request.value = storeReq.value

        #Unsantized Key
        read.event.store_request.key = "tmp/../file/.."
        read.event.store_request.value = storeReq.value

        print(read)'''
        ## DELETE BEFORE HERE


        # Formulate Response
        response = nstp_v2_pb2.IDSMessage()
        dec = nstp_v2_pb2.IDSDecision()
        dec.event_id = read.event.event_id

        #Check for Sec1/Sec2 Advisory/ Spec
        dec.allow = sanitize(read) and spec(read) and bufferOverflowCheck(read)
        response.decision.event_id = dec.event_id
        response.decision.allow = dec.allow

        # Check if at Sec3 --> Terminate connection
        if not maxConcurrency(read):
            response = terminate_connection(read)

        if "connection_established" in str(read.event):
            maxSingleIPConnections(msg, s)

        # Send Message back prefixed with length 
        sentMsg = response.SerializeToString()
        print("SENT MSG", sentMsg)
        sentLen = struct.pack("!H", len(sentMsg))
        s.send(sentLen + sentMsg)
        print("IDS RESPONSE: ", response)

main()
