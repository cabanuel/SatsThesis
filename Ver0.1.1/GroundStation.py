#developed in python 3.5
import socket
import select
import os
import sys
from  struct import *
from math import *
# set IP address of source machine for sending, and dummy port (just filler)

CUDP_IP = "0.0.0.0"
CUDP_PORT = 0

IP_address_src = '192.168.1.2'
IP_address_dst = '192.168.1.1'
# set the length of max read (e.g. cadet can only send 77 bytes at a time)
readLen = 77
# set the length of the actual data packet (readLen - IPv4 header - NERDP header)
dataPacketLen = readLen - 20 -4

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
        
# *****************************************************************************************************************
# This is where we determine out NERDP header and append the payload and send the packets
# portbyte is a byte containing the source port onthe first 4 bits of the byte, and the destination port in the last 4
# This allows for 16 (0-15) ports for source and destinations
# Each packet has the ip_header structure + the NERDP_header structure + and the payload
# the header is 4 bytes, each other message extends that header by 3 bytes, but data transmission strictly 4 bytes per
# header. These packets get rerouted because they don't go to port 0
# 
# Currently the only reserved port is port 0, that is for ACK, SYN, REQ, MIS
# Future implementations may reserve port 1 for State of health and telemetry data

# *****************************************************************************************************************

    # Packet type used to request object
    if packetType == 'REQ':
        # Request must include a data port (not 0,1,2) on which the data will be sent
        reqPortByte = (str(reqPort).encode('ascii'))
        reqPortByte = pack('B',reqPort)
        data = packetType.encode('ascii') + reqPortByte + payload # REQ (3 bytes), payload = REQUESTED PORT+objectname
        # REQ packets get sent from port 0 to port0
        srcport = 0
        dstport = 0
        # Store the source port on the upper 4 bits of the portbyte, and the destination port on the lower 4 bits
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        # Pack the header to 4 bytes total
        NERDP_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+NERDP_header+data, (IP_address_dst, dstport));

    # Packet type used to acknowlege request packet 
    if packetType == 'ACK':
        data = packetType.encode('ascii') + payload #payload = ACK, OTP_OFFSET (8 bytes) , OBJ_SIZE (8 bytes) 
        # ACK packets get sent from port 0 to port 0
        srcport = 0
        dstport = 0
        # Store the source port on the upper 4 bits of the portbyte, and the destination port on the lower 4 bits
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        NERDP_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+NERDP_header+data, (IP_address_dst, dstport));

    # Packet type used to signal end of transmission, whether from EOF or if the ground station terminates 
    if packetType == 'FIN':
        data = packetType.encode('ascii') + payload #empty payload
        # FIN packets get sent from port 0 to port 0
        srcport = 0
        dstport = 0
        # Store the source port on the upper 4 bits of the portbyte, and the destination port on the lower 4 bits
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        # Pack the header to 4 bytes total
        NERDP_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+NERDP_header+data, (IP_address_dst, dstport));

    # Packet type used to synchronize and request any retransmissions of the 255 packet frame
    if packetType == 'SYN':
        data = packetType.encode('ascii') + payload #payload = SYN, NULL 
        # SYN packets get sent from port 0 to port 0
        srcport = 0
        dstport = 0
        # Store the source port on the upper 4 bits of the portbyte, and the destination port on the lower 4 bits
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        NERDP_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+NERDP_header+data, (IP_address_dst, dstport));

    # Packet type used to indicate the missing packets and request retransmission
    if packetType == 'MIS':
        data = packetType.encode('ascii') + payload #payload = MIS, Packet numbers where each byte is one packetID 
        # MIS packets get sent from port 0 to port 0
        srcport = 0
        dstport = 0
        # Store the source port on the upper 4 bits of the portbyte, and the destination port on the lower 4 bits
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        # Pack the header to 4 bytes total
        NERDP_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+NERDP_header+data, (IP_address_dst, dstport));

    # Packet type used to initiate transmission of next 255 packet frame and continue data transmission (end of retransmission)
    if packetType == 'CON':
        data = packetType.encode('ascii') + payload #payload = MIS, Packet numbers where each byte is one packetID
        # CON packets get sent from port 0 to port 0 
        srcport = 0
        dstport = 0
        # Store the source port on the upper 4 bits of the portbyte, and the destination port on the lower 4 bits
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        # Pack the header to 4 bytes total
        NERDP_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+NERDP_header+data, (IP_address_dst, dstport));

    # Packet type used to indicate payload data packet
    if packetType == 'DAT':
        data = payload # payload is the data being sent
        # packets get sent from port 2 to requested port
        srcport = 2 
        dstport = reqPort
        # Store the source port on the upper 4 bits of the portbyte, and the destination port on the lower 4 bits
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        # Pack the header to 4 bytes total
        NERDP_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+NERDP_header+data, (IP_address_dst, dstport));

    if packetType == 'SRQ': #request
        data = payload.encode('ascii') # payload = 'SOHREQ'
        # SOH packets get sent from port 1 to port 1
        srcport = 1 
        dstport = 1
        # Store the source port on the upper 4 bits of the portbyte, and the destination port on the lower 4 bits
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        # Pack the header to 4 bytes total
        NERDP_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+NERDP_header+data, (IP_address_dst, dstport));

    if packetType == 'SRP': #response
        data = packetType.encode('ascii') + payload # payload = 'SOHRSP' + data of SOH
        # SOH packets get sent from port 1 to port 1
        srcport = 1 
        dstport = 1
        # Store the source port on the upper 4 bits of the portbyte, and the destination port on the lower 4 bits
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        # Pack the header to 4 bytes total
        NERDP_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+NERDP_header+data, (IP_address_dst, dstport));

def main():
        while True:
            print('*MAIN MENU*')
            print('1. SEND OBJ REQ AND CAPTURE DATA')
            # TODO:
            # print('2. SEND REQ AND CAPTURE SOH')
            # print('3. SEND UPL AND SEND OBJECT')

            # input the response, some input validation
            try:
                response = int(input('PLEASE ENTER NUMBER OF DESIRED ACTION: '))
                break
            except:
                print('Exiting')
                sys.exit()

        # Requesting an object from the Satellite
        if response == 1:

            # get name and requested object on data port between 3 and 15
            obj = str(input('ENTER NAME OF REQUESTED OBJECT: '))
            reqPort = int(input('ENTER NUMBER OF REQUESTED DATA PORT: '))
            
            # Build the REQuest packet
            packetID = 0
            packetType = 'REQ'
            payload = obj.encode('ascii')

            # send REQuest packet with object name, and the requested port
            sendPacket(IP_address_dst, IP_address_src, packetID, packetType, payload, reqPort)

            # start recieving the object
            print('SWITCHING TO RECEIVING MODE')
            # recieve each packet (77 bytes)
            dataSent = 0
            paketID = 0
            totalPacketsRcvd = 0
            targetPacketsRcvd = 0 
            recvdMsgBuffer = {}
            repeatPackets = ''
            #  TESTING RETRANSMISSION - remove line 241 before operation
            x = 0
            f = open('test.txt', 'wb')            


            # start data collection

            # TODO: add functionality for state of health packets sent to port 0
            # print('THIS IS USED FOR NON DATA TRANSFERR PACKETS')

            # else it must all be data being sent to reqport
            while True:

                # PAYLOAD LENGTH HERE IS SET AT 77 FOR THE MODEL USED
                # CAN BE CHANGED TO N BYTES.
                # recieve the readLen number of bytes
                packetRcvd = s.recvfrom(readLen)
                # get rid of the IP header
                packetRcvd = packetRcvd[0]
                # unpack the portbyte and get the src and dst ports
                portByte   = format(int(packetRcvd[20]),'02x')
                srcport = int(portByte[0],16)
                dstport = int(portByte[1],16)
                # get the checksum (2 bytes)
                checksum   = packetRcvd[21:23]
                # packetID # (between 0-255)
                packetID   = packetRcvd[23]
                # the rest is payload
                payload    = packetRcvd[24:]
                # get payload type
                packetType = payload[0:3].decode('ascii')

                if dstport == 0:
                    if packetType == 'ACK':

                        # TODO set a timer for ACK, if the next packet received

                        # parse ACK
                        # ACK is added to the written file
                        # 0-3 ACK, 3-10 OTP offset, 10-17 obj size

                        ackPayload = payload[3:19]
                        # unpack the payload
                        ackPayload = unpack('!QQ',ackPayload)
                        # get one time pad offset and object size from payload
                        OTP_OFFSET = ackPayload[0]
                        OBJ_SIZE = ackPayload[1] # in bytes

                        # how many packets is ground expecting
                        targetPacketsRcvd = ceil(OBJ_SIZE/dataPacketLen) + 1 #total data/packetsize + the ACK packet
                        # the length of the last packet 
                        lastPacketLen = OBJ_SIZE%dataPacketLen
                        # how many packets are in the last frame
                        packetsInLastFrame = targetPacketsRcvd%256
                        # get the payload and say set the ack flag so we know we have received the ack
                        # we need the ack flag to trigger ack retransmission, this is important to get the 
                        # Object size and determine retransmission
                        recvdMsgBuffer[packetID] = payload
                        ackFlag = 1
                        # we have received 1 packet
                        totalPacketsRcvd += 1

                    # if we receive a SYNchronization packet, means we have received 256 packets of data
                    # and the satellite has NOT sent all of the object yet
                    if packetType == 'SYN':

                        # trigger check for missing/corrupted packets, then CON
# # DELETE PACKET TEST START REMOVE BEFORE FLIGHT
#                         if x == 0:
#                             print('***************REPEAT TEST', recvdMsgBuffer[0])
#                             del recvdMsgBuffer[0]
#                             totalPacketsRcvd -=1
#                             x+=1
#                             ackFlag = 0
# # DELETE PACKET TEST END

                        # if we received SYN we need to check if we are missing any packets
                        # ground must have received packets 0-255
                        repeatPackets = ''
                        for i in range(256):
                            # use the key of the received message buffer dictionary as the packet ID
                            if i in recvdMsgBuffer:
                                # if packet exists, append '0' to a string
                                repeatPackets += '0'
                                continue
                            else:
                                # if packet doesnt exist, append '1'
                                repeatPackets += '1'
                        # we now have a string of 0's and 1's of len 256 where the position on the list
                        # determines the packetID
                        if '1' in repeatPackets:
                            # if there's a '1' in this we trigger retransmission
                            i = 0
                            missingPack = []
                            while i < 32:
                                # we take 8 characters at a time, treat them as int and pack them 
                                # into a byte. this way we can get 256 packets packed into 32 bytes
                                missingPack.append(int(repeatPackets[i*8:i*8+8],2))
                                i+=1
                            # pack the first byte (8 packets per byte) 
                            payload = pack('!B', missingPack[0])
                            # pack the rest of the 32 bytes
                            for i in range(1,32):
                                payload += pack('!B', missingPack[i])

                            # send the MIS packet requesting retransmission with the 32 bytes of
                            # missing packet information. Packet ID = 255, ports are 0 and 0
                            packetID = 255
                            sendPacket(IP_address_dst, IP_address_src, packetID, 'MIS', payload, 0)
                            continue
                        else:
                            # write the packets to file, send a CON packet, and get the next 255 packets
                            for i in recvdMsgBuffer:
                                # write the packets (in order including the ack)
                                f.write(recvdMsgBuffer[i])
                            # clear the dictionary
                            recvdMsgBuffer= {}
                            # send a CONtinute packet requesting the next frame of packets
                            packetID = 255
                            payload = '0' #NULL payload
                            payload = payload.encode('ascii')
                            sendPacket(IP_address_dst, IP_address_src, packetID, 'CON', payload, 0)
                            continue


                            # If ACK flag is missing, we just treat it as data packet for retransmission
                            # IFF we received at least 256 data packets, we determine this by receiving the SYN packet


                    # If we receive a FINish packet, it means the satellite has sent less than 256 packets in this frame
                    # and has reached EOF
                    if packetType == 'FIN':
                        repeatPackets = ''

# # DELETE PACKET TEST START, REMOVE BEFORE FLIGHT
#                         if x == 0:
#                             print('***************REPEAT TEST', recvdMsgBuffer[0])
#                             del recvdMsgBuffer[0]
#                             totalPacketsRcvd -=1
#                             x+=1
#                             ackFlag = 0
# # DELETE PACKET TEST END
                        # if we are missing the ACK packet, and the flag has not been triggered indicating
                        # we are still on the first frame, we must request it alone
                        # we cannot do retranmission on frames less than 256 packets without the OBJ_SIZE
                        if (('0' not in recvdMsgBuffer) and (totalPacketsRcvd < 256) and (ackFlag == 0)):
                            # repeating ACK
                            # only '1' in retranmission 256 string is ACK flag
                            repeatPackets +='1'
                            repeatPackets += '0'*255

                            i = 0
                            missingPack = []
                            while i < 32:
                                # we take 8 characters at a time, treat them as int and pack them 
                                # into a byte. this way we can get 256 packets packed into 32 bytes
                                missingPack.append(int(repeatPackets[i*8:i*8+8],2))
                                i+=1
                            # pack the first one
                            payload = pack('!B', missingPack[0])
                            # pack the rest
                            for i in range(1,32):
                                payload += pack('!B', missingPack[i])
                            # send MIS packet
                            packetID = 255
                            sendPacket(IP_address_dst, IP_address_src, packetID, 'MIS', payload, 0)
                            continue


                        # if we get a FIN and we hace the ACK packet we can then just trigger retransmission as normal
                        for i in range(packetsInLastFrame):
                            # use the key of the received message buffer as the packet ID
                            if i in recvdMsgBuffer:
                                # if packetID is there, then we append '0' to a string
                                repeatPackets += '0'
                                continue
                            else:
                                # if not we append '1'
                                repeatPackets += '1'
                        # since we didnt receive a full frame, we must then pad the remainder packets
                        # with 0's to reach the 32 Bytes
                        while len(repeatPackets) < 256:
                            repeatPackets += '0'

                        # is retranmsission needed? 
                        if '1' in repeatPackets:
                            # if there is a 1, yes
                            i = 0
                            missingPack = []
                            while i < 32:
                                # we take 8 characters at a time, treat them as int and pack them 
                                # into a byte. this way we can get 256 packets packed into 32 bytes
                                missingPack.append(int(repeatPackets[i*8:i*8+8],2))
                                i+=1

                            # pack the first byte
                            payload = pack('!B', missingPack[0])

                            # pack the rest of the 32 bytes
                            for i in range(1,32):
                                payload += pack('!B', missingPack[i])

                            # Send MIS packet requesting retransmission
                            packetID = 255
                            sendPacket(IP_address_dst, IP_address_src, packetID, 'MIS', payload, 0)
                            continue
                        else:
                            # write packets to file,  send a FIN packet and exit
                            for i in recvdMsgBuffer:
                                f.write(recvdMsgBuffer[i])
                            packetID = 255
                            payload = '0' #NULL payload
                            payload = payload.encode('ascii')
                            sendPacket(IP_address_dst, IP_address_src, packetID, 'FIN', payload, 0)
                            break


                # if dstport != 0 then it is the reqport (for now) and it is data and we must append it to the dict    
                recvdMsgBuffer[packetID] = payload
                totalPacketsRcvd +=1

            # close file
            f.close()
            print('DONE')
            print('SAVING {}'.format(obj))
            print('TOTAL PACKETS #', totalPacketsRcvd)
            # reset ack flag
            ackFlag = 0            





# *******************************
# *******************************
# Begin Ground logic
# *******************************
# *******************************
if __name__ == '__main__':
    main()