#!/usr/bin/env python3
import nstp_v2_pb2
import sys
import socket
import struct

p = sys.argv[0]
sockFile = sys.argv[1]

def main():
    print(sockFile)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sockFile)

    while True:
        msg = s.recv(1024)
        length = struct.unpack("!H", msg[0:2])[0]
        print(length)
        msg = msg[2:]
        read = nstp_v2_pb2.IDSMessage()
        print(read.event.event_id)
        read.ParseFromString(msg)
        print (read)

        response = nstp_v2_pb2.IDSMessage()
        dec = nstp_v2_pb2.IDSDecision()
        dec.event_id = read.event.event_id
        dec.allow = True
        r =response.decision.add()
        r.decision
        #response.dec.add()

        s.send(response.SerializeToString())
        print(dec)
        print(dec.SerializeToString())
        continue

main()
