#developed in python 3.5
import socket
import os
from  struct import *

# set IP address of source machine for sending, and dummy port (just filler to test on VMs on same network)

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

# This is the structure for sending ALL types of packets, taking in only certain parameters
# This will also fix the IP header and take charge of sending the IP packet
# For testing in VM network, 20 bytes are lost out of the 77 target len to the IP header
# This can be avoided in the radio operation, since the packet transfer will be taken care of
# by something like AX.25 protocol

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
        reqPortByte = (str(reqPort).encode('ascii'))
        reqPortByte = pack('B',reqPort)
        data = packetType.encode('ascii') + reqPortByte + payload # REQ (3 bytes), payload = REQUESTED PORT+object
        srcport = 0
        dstport = 0
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        NERDP_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+NERDP_header+data, (IP_address_dst, dstport));

    # Packet type used to acknowlege request packet 
    if packetType == 'ACK':
        data = packetType.encode('ascii') + payload #payload = ACK, OTP_OFFSET (8 bytes) , OBJ_SIZE (8 bytes) 
        srcport = 0
        dstport = 0
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        NERDP_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+NERDP_header+data, (IP_address_dst, dstport));

    # Packet type used to signal end of transmission, whether from EOF or if the ground station terminates 
    if packetType == 'FIN':
        data = packetType.encode('ascii') + payload #empty payload
        srcport = 0
        dstport = 0
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        NERDP_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+NERDP_header+data, (IP_address_dst, dstport));

    # Packet type used to synchronize and request any retransmissions of the 255 packet frame
    if packetType == 'SYN':
        data = packetType.encode('ascii') + payload #payload = SYN, NULL 
        srcport = 0
        dstport = reqPort
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        NERDP_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+NERDP_header+data, (IP_address_dst, dstport));

    # Packet type used to indicate the missing packets and request retransmission
    if packetType == 'MIS':
        data = packetType.encode('ascii') + payload #payload = MIS, Packet numbers where each byte is one packetID 
        srcport = 0
        dstport = 0
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        NERDP_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+NERDP_header+data, (IP_address_dst, dstport));

    # Packet type used to initiate transmission of next 255 packet frame and continue data transmission (end of retransmission)
    if packetType == 'CON':
        data = packetType.encode('ascii') + payload #payload = MIS, Packet numbers where each byte is one packetID 
        srcport = 0
        dstport = 0
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        NERDP_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+NERDP_header+data, (IP_address_dst, dstport));

    # Packet type used to indicate payload data packet
    if packetType == 'DAT':
        data = payload # payload is the data being sent
        srcport = 2 
        dstport = reqPort
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        NERDP_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+NERDP_header+data, (IP_address_dst, dstport));

    if packetType == 'SRQ': #request
        data = payload.encode('ascii') # payload = 'SOHREQ'
        srcport = 1 
        dstport = 1
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        NERDP_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+NERDP_header+data, (IP_address_dst, dstport));

    if packetType == 'SRP': #response
        data = packetType.encode('ascii') + payload # payload = 'SOHRSP' + data of SOH
        srcport = 1 
        dstport = 1
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        NERDP_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+NERDP_header+data, (IP_address_dst, dstport));

def main():
    while True:
        print('*LISTENING...*')
        packetRcvd = s.recvfrom(77)
        packetRcvd = packetRcvd[0]
        portByte   = format(int(packetRcvd[20]),'02x')
        checksum   = packetRcvd[21:23]
        packetID   = packetRcvd[23]
        payload    = packetRcvd[24:]

        OTP_OFFSET = 0
        
        # get dstport and srcport
        srcport = int(portByte[0],16)
        dstport = int(portByte[1],16)


        if dstport == 0:
            packetType = payload[0:3].decode('ascii')

            if packetType == 'REQ':
                # we need to send ACK
                reqPort = payload[3]
                objReq  = payload[4:].decode('ascii') #object requested
                objReqSizeDec = os.stat(objReq).st_size


                # pack the objsize and the OTP offset as long unsigned ints
                payload = pack('!QQ', OTP_OFFSET, objReqSizeDec) 
                print('*SENDING ACK*')
                sendPacket(IP_address_dst, IP_address_src, 0, 'ACK', payload, 0)

                # TIME TO SEND DATA
                dataSent = 0
                packetID = 0
                f = open(objReq, 'rb')
                # data sent dictionary
                packetSentBuff = {}
                packetType = 'ACK'
                # used to say this is the first frame in case of needed ACK retransmission
                ackFlag = 0
                packetSentBuff[packetID] = packetType.encode('ascii') + payload
                packetID +=1 
                print('*SENDING DATA*')
                while dataSent < objReqSizeDec:
                    payload = f.read(53)
                    if packetID < 256: #and len(payload) != 0:
                        # payload = f.read(53)
                        packetSentBuff[packetID] = payload
                        sendPacket(IP_address_dst, IP_address_src, packetID, 'DAT', payload, reqPort)
                        dataSent += 53
                        packetID += 1
                    else:
                        while True:
                           # send SYN
                            # print(packetSentBuff)
                            payload = '0'
                            payload = payload.encode('ascii')
                            print('**************SENDING SYN')
                            sendPacket(IP_address_dst, IP_address_src, 255, 'SYN', payload, 0)
                            # listen for MIS packet
                            packetRcvd = s.recvfrom(77)
                            packetRcvd = packetRcvd[0]
                            portByte   = format(int(packetRcvd[20]),'02x')
                            checksum   = packetRcvd[21:23]
                            packetID   = packetRcvd[23]
                            payload    = packetRcvd[24:]


                            # the MIS/CONT segment of the payload
                            packetType = payload[0:3].decode('ascii')
                            missingPackets = payload[3:]
                            print('************** Packet Type Recvd', packetType)

                            # first we check that we didnt get a CONtinue message. if CON we are done retransmitting

                            if packetType == 'CON':
                                print('***************CON RECVD')
                                # reset the packet ID
                                packetID = 0
                                ackFlag = 1
                                break

                            if packetType == 'FIN':
                                dataSent = objReqSize
                                break

                            # every 8 bits inidcates 1 packet
                            # if bit n is 1 it means packet n was missing and needs
                            # to be retransmitted, if 0 no retransmission.
                            # need to build a list of 1 and 0s of packets that need to be
                            # retransmitted. Index n will be the packet number
                            # 256 bits (n = 0 through 255, where n =0 is the ack packet on first
                            # session of 256 packets)

                            # set up index for packets
                            i = 0
                            missingPacketsBin = ''
                            print(len(missingPackets))
                            while i < len(missingPackets):
                                # take byte number i, convert it to binary of type str in format
                                # format takes the integer converts it to binary, 
                                missingPacketsBin = missingPacketsBin + format(int(missingPackets[i]), '08b')
                                # now we increase the counter
                                i += 1


                            
                            i = 0
                            while i < len(missingPacketsBin):
                                if missingPacketsBin[i] == '1':
                                    print(packetSentBuff)
                                    print('i =======',i)
                                    print('*RETRANSMITTING*', packetSentBuff[i])
                                    payload = packetSentBuff[i]
                                    print('PAYLOAD OF ACK', payload)
                                    if payload[0:3].decode('ascii') == 'ACK' and ackFlag == 0:
                                        packetID = 0
                                        sendPacket(IP_address_dst, IP_address_src, packetID, 'DAT', payload, 0)

                                    else:        
                                            packetID = i
                                            sendPacket(IP_address_dst, IP_address_src, packetID, 'DAT', payload, reqPort)
                                i+=1
                                        # after this go back to the SYN
                            # we either get a MIS request or a CON request




                while True:
                   # send FIN
                    # print(packetSentBuff)
                    payload = '0'
                    payload = payload.encode('ascii')
                    sendPacket(IP_address_dst, IP_address_src, 255, 'FIN', payload, 0)

                    print('*SENT FIN PACKET AWAITING FIN RESPONSE')

                    # listen for MIS packet
                    packetRcvd = s.recvfrom(77)
                    packetRcvd = packetRcvd[0]
                    portByte   = format(packetRcvd[20],'02x')
                    checksum   = packetRcvd[21:23]
                    packetID   = packetRcvd[23]
                    payload    = packetRcvd[24:]

                    # the MIS/CONT segment of the payload
                    packetType = payload[0:3].decode('ascii')
                    missingPackets = payload[3:]

                    # first we check that we didnt get a CONtinue message. if CON we are done retransmitting

                    if packetType == 'FIN':
                        print('FIN RECEIVED')
                        # reset the packet ID
                        packetID = 0
                        break

                    # every 8 bits inidcates 1 packet
                    # if bit n is 1 it means packet n was missing and needs
                    # to be retransmitted, if 0 no retransmission.
                    # need to build a list of 1 and 0s of packets that need to be
                    # retransmitted. Index n will be the packet number
                    # 256 bits (n = 0 through 255, where n =0 is the ack packet on first
                    # session of 256 packets)


                    # TODO: this means the packet has a MIS tag and port 0
                    # useful for threading (future work)


                    # set up index for packets
                    i = 0
                    missingPacketsBin = ''
                    while i < len(missingPackets):
                        # take byte number i, convert it to binary of type str in format
                        # format takes the integer converts it to binary, 
                        missingPacketsBin = missingPacketsBin + format(int(missingPackets[i]), '08b')
                        # now we increase the counter
                        i += 1
                    # after getting the 32 bytes, and convering them to binary, we iterate over
                    # the string treating the index as the index for packet. if i == 1, then 
                    # we go back to the dictionary and retransmit. if packets retransmitted ==0
                    # we set packetID = 0, purge the dictionary, and send the next 255 packets 
                    # of data


                    i = 0
                    while i < len(missingPacketsBin):
                        if missingPacketsBin[i] == '1':
                            print(packetSentBuff)
                            print('i =======',i)
                            print('*RETRANSMITTING*', packetSentBuff[i])
                            payload = packetSentBuff[i]
                            print('PAYLOAD OF ACK', payload)
                            if payload[0:3].decode('ascii') == 'ACK' and ackFlag == 0:
                                packetID = 0
                                sendPacket(IP_address_dst, IP_address_src, packetID, 'DAT', payload, 0)

                            else:        
                                    packetID = i
                                    sendPacket(IP_address_dst, IP_address_src, packetID, 'DAT', payload, reqPort)
                        i+=1
                    # after this go back to the SYN
                    # we either get a MIS request or a CON request




                




# *******************************
# *******************************
# Begin SAT logic
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

# get size of file 
# import os
# >>> os.stat('receiver.py').st_size
# 901

