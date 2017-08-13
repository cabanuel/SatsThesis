#developed in python 3.5
import socket
import os
from  struct import *
from math import *

# set IP address of source machine for sending, and dummy port (just filler)

CUDP_IP = "0.0.0.0"
CUDP_PORT = 0

IP_address_src = '192.168.1.3'
IP_address_dst = '192.168.1.2'
# set the length of max read (e.g. cadet can only send 77 bytes at a time)
payloadSize = 77

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
     
    # THE IP HEADER, THE IP HEADER NEVER CHANGES 

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


    if packetType == 'CON':
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

    if packetType == 'SRQ': #request
        data = payload.encode('ascii') # payload = 'SOHREQ'
        srcport = 1 
        dstport = 1
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        udp_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+udp_header+data, (IP_address_dst, dstport));

    if packetType == 'SRP': #response
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
        # print('2. SEND REQ AND CAPTURE SOH')

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
            dataSent = 0
            paketID = 0
            totalPacketsRcvd = 0
            targetPacketsRcvd = 0 
            recvdMsgBuffer = {}
            repeatPackets = ''
            #  TESTING RETRANSMISSION
            x = 0
            f = open('test.txt', 'wb')            


            # start data collection

            # TODO: add functionality for state of health packets sent to port 0
            # print('THIS IS USED FOR NON DATA TRANSFERR PACKETS')

            # else it must all be data being sent to reqport
            while True:
                # dataSent = 0
                # paketID = 0 
                # f = open(obj, 'rb')
                # PAYLOAD LENGTH HERE IS SET AT 77 FOR THE MODEL USED
                # CAN BE CHANGED TO N BYTES.
                packetRcvd = s.recvfrom(payloadSize)
                packetRcvd = packetRcvd[0]
                print(packetRcvd)
                # packetsRecvd +=1
                # dataSent += 77
                portByte   = format(int(packetRcvd[20]),'02x')
                checksum   = packetRcvd[21:23]
                packetID   = packetRcvd[23]
                print('***** PACKET ID TYPE:', type(packetID))
                payload    = packetRcvd[24:]
                srcport    = int(portByte[0],16)
                dstport    = int(portByte[1],16)
                packetType = payload[0:3].decode('ascii')
                print('packet type', packetType)


                if dstport == 0:
                    if packetType == 'ACK':

                        # parse ACK
                        # ACK is added to the written file
                        # 0-3 ACK, 3-10 OTP offset, 10-17 obj size

                        ackPayload = payload[3:19]

                        ackPayload = unpack('!QQ',ackPayload)
                        OTP_OFFSET = ackPayload[0]
                        OBJ_SIZE = ackPayload[1] # in bytes
                        targetPacketsRcvd = ceil(OBJ_SIZE/53) + 1 #total data/packetsize + the ACK packet
                        lastPacketLen = OBJ_SIZE%53
                        packetsInLastFrame = targetPacketsRcvd%256
                        # print(targetPacketsRcvd)
                        recvdMsgBuffer[packetID] = payload
                        print('PAYLOAD OF ACK:::::::::::', payload)
                        ackFlag = 1

                        totalPacketsRcvd += 1


                    if packetType == 'SYN':
                        # trigger check for missing/corrupted packets, then CON
# DELETE PACKET TEST START
                        if x == 0:
                            print('***************REPEAT TEST', recvdMsgBuffer[0])
                            del recvdMsgBuffer[0]
                            totalPacketsRcvd -=1
                            x+=1
                            ackFlag = 0
# DELETE PACKET TEST END


                        repeatPackets = ''
                        for i in range(256):
                            if i in recvdMsgBuffer:
                                repeatPackets += '0'
                                continue
                            else:
                                repeatPackets += '1'
                        if '1' in repeatPackets:
                            i = 0
                            missingPack = []
                            while i < 32:
                                missingPack.append(int(repeatPackets[i*8:i*8+8],2))
                                i+=1

                            payload = pack('!B', missingPack[0])

                            for i in range(1,32):
                                payload += pack('!B', missingPack[i])

                            packetID = 255
                            print('SENDING MIS in SYN', repeatPackets)
                            sendPacket(IP_address_dst, IP_address_src, packetID, 'MIS', payload, 0)
                            continue
                        else:
                            # write the packets to file, send a CON packet, and get the next 255 packets
                            for i in recvdMsgBuffer:
                                f.write(recvdMsgBuffer[i])
                            recvdMsgBuffer= {}

                            packetID = 255
                            payload = '0' #NULL payload
                            payload = payload.encode('ascii')
                            print('**************************Sending CON')
                            sendPacket(IP_address_dst, IP_address_src, packetID, 'CON', payload, 0)
                            continue






                    if packetType == 'FIN':
                        repeatPackets = ''

# DELETE PACKET TEST START
                        if x == 0:
                            print('***************REPEAT TEST', recvdMsgBuffer[0])
                            del recvdMsgBuffer[0]
                            totalPacketsRcvd -=1
                            x+=1
                            ackFlag = 0
# DELETE PACKET TEST END

                        if (('0' not in recvdMsgBuffer) and (totalPacketsRcvd < 256) and (ackFlag == 0)):
                            # repeating ACK
                            print('REREQUESTING ACK !*!*!*!**!*!*!*!*!*!***!*!*!*!*!*!*!*!**!*!*!*!*!*!*!*!*')
                            repeatPackets +='1'
                            repeatPackets += '0'*255

                            i = 0
                            missingPack = []
                            while i < 32:
                                missingPack.append(int(repeatPackets[i*8:i*8+8],2))
                                i+=1

                            payload = pack('!B', missingPack[0])

                            for i in range(1,32):
                                payload += pack('!B', missingPack[i])

                            packetID = 255
                            print('***********SENT MIS', repeatPackets)
                            sendPacket(IP_address_dst, IP_address_src, packetID, 'MIS', payload, 0)
                            continue





                        print('$$$$$$$$$$$$$$$Packets in last frame', packetsInLastFrame)
                        for i in range(packetsInLastFrame):
                            if i in recvdMsgBuffer:
                                repeatPackets += '0'
                                continue
                            else:
                                repeatPackets += '1'
                        while len(repeatPackets) < 256:
                            repeatPackets += '0'

                        print('rpt ',repeatPackets)

                            

                        if '1' in repeatPackets:
                            i = 0
                            missingPack = []
                            while i < 32:
                                missingPack.append(int(repeatPackets[i*8:i*8+8],2))
                                i+=1

                            payload = pack('!B', missingPack[0])

                            for i in range(1,32):
                                payload += pack('!B', missingPack[i])

                            packetID = 255
                            print('***********SENT MIS')
                            sendPacket(IP_address_dst, IP_address_src, packetID, 'MIS', payload, 0)
                            continue
                        else:
                            # write packets to file,  send a FIN packet and exit
                            for i in recvdMsgBuffer:
                                f.write(recvdMsgBuffer[i])
                                # print('WRITING', recvdMsgBuffer )
                            packetID = 255
                            payload = '0' #NULL payload
                            payload = payload.encode('ascii')
                            sendPacket(IP_address_dst, IP_address_src, packetID, 'FIN', payload, 0)
                            break
                    # if dstport != 0 then it is the reqport (for now) and it is data and we must append it to the dict
                    
                print('SAVING')
                recvdMsgBuffer[packetID] = payload
                totalPacketsRcvd +=1

            # close file
            f.close()
            print('DONE')

            ackFlag = 0            




























            # i = 0
            # while i < 5:
            #     packetRcvd = s.recvfrom(77)
            #     packetRcvd = packetRcvd[0]    
            #     print(packetRcvd)
            #     i +=1

            # repeatFirstPacket ='01000000'
            # firstpacket = int(repeatFirstPacket,2)
            # payload = pack('B',firstpacket)
            # i = 0
            # while i < 31:
            #     payload = payload + pack('B',0)
            #     i+=1
            # # payload = payload.encode('ascii')
            # sendPacket(IP_address_dst, IP_address_src, 255, 'MIS', payload, reqPort)

            # packetRcvd = s.recvfrom(77)
            # packetRcvd = packetRcvd[0]    
            # print(packetRcvd)

            # packetRcvd = s.recvfrom(77)
            # packetRcvd = packetRcvd[0]    
            # print(packetRcvd)

            # payload = '0'
            # payload = payload.encode('ascii')
            # sendPacket(IP_address_dst, IP_address_src, 255, 'FIN', payload, reqPort)





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

    

