#developed in python 3.5
import socket
import os
from  struct import *

# set IP address of source machine for sending, and dummy port (just filler)

CUDP_IP = "0.0.0.0"
CUDP_PORT = 0

IP_address_src = '192.168.1.2'
IP_address_dst = '192.168.1.3'
# set the length of max read (e.g. cadet can only send 77 bytes at a time)
readLen = 77

# create a raw socket that will bind to the network interface, this will receive all raw packets at the OSI layer 3
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

try:
    s.bind((CUDP_IP,CUDP_PORT))
except:
    print ('ERROR BINDING CHECK PRIVS')
    sys.exit()


def sendPacket(IP_address_dst,IP_address_src, packetID, packetType, payload, reqPort):

# PAYLOAD MUST BE OF TYPE BYTES SO IT CAN BE ENCODED LATER
# IP_address_* MUST BE OF TYPE STR
# packetID MUST BE OF TYPE INT
# packetType MUST BE OF TYPE STR

    packet = '';

     #THIS IS FIXED 
    source_ip = IP_address_src

    # PASSED AS A PARAMETER AS STRING
    dest_ip = IP_address_dst 
     
    # ip header fields
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 38  # kernel will fill the correct total length
    ip_id = 54321   #Id of this packet
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_RAW
    ip_check = 0    # kernel will fill the correct checksum
    ip_saddr = socket.inet_aton ( source_ip )   #Spoof the source ip address if you want to
    ip_daddr = socket.inet_aton ( dest_ip )
     
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
     
    # the ! in the pack format string means network order
    ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
        

    # THE IP HEADER, THE IP HEADER NEVER CHANGES


    if packetType == 'REQ':
        reqPortByte = (str(reqPort).encode('ascii'))
        reqPortByte = pack('B',reqPort)
        data = packetType.encode('ascii') + reqPortByte + payload # REQ (3 bytes), OBJECT, payload = object+REQUESTED PORT
        srcport = 0
        dstport = 0
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        udp_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+udp_header+data, (IP_address_dst, dstport));

    if packetType == 'ACK':
        data = packetType.encode('ascii') + payload #payload = ACK, OTP_OFFSET (5 bytesMAX) , OBJ_SIZE (5 bytes) 
        srcport = 0
        dstport = 0
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        udp_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+udp_header+data, (IP_address_dst, dstport));

    if packetType == 'SYN':
        data = packetType.encode('ascii') + payload #payload = SYN, NULL 
        srcport = 0
        dstport = 0
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        udp_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+udp_header+data, (IP_address_dst, dstport));

    if packetType == 'MIS':
        data = packetType.encode('ascii') + payload #payload = MIS, Packet numbers where each byte is one packetID 
        srcport = 0
        dstport = 0
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        udp_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+udp_header+data, (IP_address_dst, dstport));

    if packetType == 'DAT':
        data = payload # payload is the data being sent
        srcport = reqPort 
        dstport = 2
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        udp_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+udp_header+data, (IP_address_dst, dstport));

    if packetType == 'FIN':
        data = packetType.encode('ascii') + payload #payload = FIN, NULL 
        srcport = 0
        dstport = 0
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        udp_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+udp_header+data, (IP_address_dst, dstport));

    if packetType == 'SOHREQ': #request
        data = payload.encode('ascii') # payload = 'SOHREQ'
        srcport = 1 
        dstport = 1
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        udp_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+udp_header+data, (IP_address_dst, dstport));

    if packetType == 'SOHRSP': #response
        data = packetType.encode('ascii') + payload # payload = 'SOHRSP' + data of SOH
        srcport = 1 
        dstport = 1
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        udp_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+udp_header+data, (IP_address_dst, dstport));

def main():
    while True:
        print('*MAIN MENU*')
        print('1. SEND OBJ REQ AND CAPTURE DATA')
        print('2. SEND REQ AND CAPTURE SOH')

        response = int(input('PLEASE ENTER NUMBER OF DESIRED ACTION: '))

        if response == 1:

            obj = str(input('ENTER NAME OF REQUESTED OBJECT: '))
            reqPort = int(input('ENTER NUMBER OF REQUESTED DATA PORT: '))
            
            packetID = 0
            packetType = 'REQ'
            payload = obj.encode('ascii')

            sendPacket(IP_address_dst, IP_address_src, packetID, packetType, payload, reqPort)

            print('SWITCHING TO RECEIVING MODE')
            # recieve the packet (77 bytes)
            while True:
                packetRcvd = s.recvfrom(77)
                packetRcvd = packetRcvd[0]    
                print(packetRcvd)





# *******************************
# *******************************
# Begin Ground logic
# *******************************
# *******************************
if __name__ == '__main__':
    main()











    # # recieve the packet (77 bytes)
    # packetRcvd = s.recvfrom(77)
    # packetRcvd = packetRcvd[0]

    # # should be 77 or less
    # print(len(packetRcvd))
    # # this includes the IP header of 20 bytes.

    # # used to convert from bytes to ascii 
    # # print((packetRcvd[29:]).decode('ascii'))

    # # get the first byte of the payload (byte #20) this it the dst port/src port
    # print(packetRcvd[24:])

    

