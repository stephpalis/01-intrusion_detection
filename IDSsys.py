#!/usr/bin/env python3
import nstp_v2_pb2
import sys
import socket
import struct

p = sys.argv[0]
sockFile = sys.argv[1]

# Ensure that it doesn't violate the NSTPv2 specification
def spec(msg):
    print("TESTING SPEC")
    #TODO should this be != 1 or != 2
    if "client_hello" in str(msg.event):
        if msg.event.client_hello.major_version != 2:
            print("Bad Major")
            return False
    return True

# NSTP-SEC-2020-0001
def sanitize(msg):
    print("Sanitizing")
    if "load_request" in str(msg.event):
        print("Analyzing Load request")
        if "/" in msg.event.load_request.key or ".." in msg.event.load_request.key:
            print("Load Request contains / or ..")
            return False
    elif "store_request" in str(msg.event):
        print("Analyzing store request")
        if "/" in msg.event.store_request.key or ".." in msg.event.store_request.key:
            print("Store Request contains / or ..")
            return False
    return True

# NSTP-SEC-2020-0002
def bufferOverflowCheck(msg):
    print("Checking buffer overflow")
    storeReq = msg.event.store_request

    if storeReq != 0:
        print("Checking store request")
        if len(storeReq.key) > 512:
            print("Failed store request")
            return False
    return True

def main():
    print(sockFile)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sockFile)

    while True:
        print("READING")
        # Recieve Message
        msg = s.recv(1024)
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
        print(read.event.event)#connection_established)
        read.event.connection_established = storeReq'''

        # Formulate Response
        response = nstp_v2_pb2.IDSMessage()
        dec = nstp_v2_pb2.IDSDecision()
        dec.event_id = read.event.event_id
        # TODO new method for keys with '/' and '..' for loadRequest and storeRequest
        dec.allow = sanitize(read) and spec(read) and bufferOverflowCheck(read)

        '''#TODO delete
        if dec.event_id == 128:
            dec.allow = False
        ## TODO END delete'''

        response.decision.event_id = dec.event_id
        response.decision.allow = dec.allow

        # Send Message back prefixed with length 
        sentMsg = response.SerializeToString()
        print("SENT MSG", sentMsg)
        sentLen = struct.pack("!H", len(sentMsg))
        s.send(sentLen + sentMsg)
        print("IDS RESPONSE: ", response)
        continue

main()
