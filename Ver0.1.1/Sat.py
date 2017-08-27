#developed in python 3.5
import socket
import os
import select
from  struct import *

#  ********************************************************************************************************************
# Establish some parameters from user:
#  ********************************************************************************************************************


# set IP address of source machine for sending, and dummy port (just filler to test on VMs on same network)

CUDP_IP = "0.0.0.0"
CUDP_PORT = 0

IP_address_src = '192.168.1.2'
IP_address_dst = '192.168.1.3'
# set the length of max read (e.g. cadet can only send 77 bytes at a time)
readLen = 77
# set the length of the actual data packet (readLen - IPv4 header - NERDP header)
dataPacketLen = readLen - 20 -4
# to vary the transmission rate we establish the timeout expecter per packet
# this is the time we expect for a packet to require for roundtrip 
# THIS IS VERY DEPENDENT ON RADIO, HARDWARE, ETC. ADJUST FOR YOUR DEVICE
packetDelay = 0.5
#  ********************************************************************************************************************
#  ********************************************************************************************************************


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
        print('*LISTENING...*')
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

        # initialize the OneTimePad Offset
        # TODO: add option for encryption in ACK packet
        OTP_OFFSET = 0
        
        # If it is a control packet it came to port 0
        if dstport == 0:
            # All control packets in the payload have a 3 letter designation (ACK, MIS...)
            packetType = payload[0:3].decode('ascii')

            # If we get a request we need to process it
            if packetType == 'REQ':
                # we need to send ACK
                # obtain the requested port
                reqPort = payload[3]
                objReq  = payload[4:].decode('ascii') #object requested
                objReqSizeDec = os.stat(objReq).st_size #object requested size


                # pack the objsize and the OTP offset as long unsigned ints
                payload = pack('!QQ', OTP_OFFSET, objReqSizeDec) 
                # send the ACK
                sendPacket(IP_address_dst, IP_address_src, 0, 'ACK', payload, 0)

                # *************************************************************
                # TIME TO SEND DATA
                # *************************************************************
                # initialize counters
                dataSent = 0
                packetID = 0
                # open the rquested file as a read only
                f = open(objReq, 'rb')
                # initialize data sent dictionary
                packetSentBuff = {}
                # need to store the ACK packet with the 3 letter designator in the payload
                packetType = 'ACK'
                # used to say this is the first frame in case of needed ACK retransmission
                ackFlag = 0
                # save the ACK packet in the dictionary
                packetSentBuff[packetID] = packetType.encode('ascii') + payload
                # increase packetID #
                packetID +=1 
                print('*SENDING DATA*')
                while dataSent < objReqSizeDec:

                    # if we havent sent 255 packets we send data
                    if packetID < 256: 
                        # read (in the test case 55 bytes) data from file
                        payload = f.read(dataPacketLen)
                        # save it to the dictionary first
                        packetSentBuff[packetID] = payload
                        # send the data packet to the requested port
                        sendPacket(IP_address_dst, IP_address_src, packetID, 'DAT', payload, reqPort)
                        # update counters
                        dataSent += dataPacketLen
                        packetID += 1
                    # if we have already sent the 255 packets and we have not sent the total object size
                    # we must send a SYN
                    else:
                        # counter for the number of SYN retransmits
                        synCounter = 0
                        while True:
                            # SYN packet retranmsission logic (timeout = packetDelay * number of packets sent +1)
                            if synCounter == 0:
                                # send SYN
                                # SYN packet has a null payload
                                payload = '0'
                                payload = payload.encode('ascii')
                                # increase the synCounter
                                synCounter +=1 
                                # Send the SYN packet to port 0
                                sendPacket(IP_address_dst, IP_address_src, 255, 'SYN', payload, 0)
                                # long wait for the retransmit
                                synRetransmit = select.select([s],[],[packetDelay*257])

                            if 0 < synCounter < 3:
                                # send SYN
                                # SYN packet has a null payload
                                payload = '0'
                                payload = payload.encode('ascii')
                                # increase the synCounter
                                synCounter +=1 
                                # Send the SYN packet to port 0
                                sendPacket(IP_address_dst, IP_address_src, 255, 'SYN', payload, 0)
                                # for retransmits we want short wait 
                                synRetransmit = select.select([s],[],[packetDelay*2])

                            if synCounter >= 3:
                                print('MAX RETRANSMITS REACHED')
                                break
                            # if we dont get data within the timeout we retransmit 2 more syns at lower wait

                            # if we dont get any data, we go back to send the syn 
                            if not synRetransmit[0]:
                                continue

                            # if we do get data, we  then recieve it and process the packet. Every SYN retransmit will have a short wait
                            
                            # TODO make the syn after MIS packet retransmission dynamic

                            # listen for MIS packet
                            packetRcvd = s.recvfrom(readLen)
                            # again get rid of IP header stuff
                            packetRcvd = packetRcvd[0]
                            # port byte is going to be zero 
                            # TODO write a check to make sure that the ports are zero
                            portByte   = format(int(packetRcvd[20]),'02x')
                            # checksum for integrity
                            checksum   = packetRcvd[21:23]
                            # packet type is by default 255
                            packetID   = packetRcvd[23]
                            # payload of MIS is 32 bytes
                            payload    = packetRcvd[24:]


                            # the MIS/CONT segment of the payload
                            packetType = payload[0:3].decode('ascii')
                            missingPackets = payload[3:]
                            
                            # first we check that we didnt get a CONtinue message. if CON we are done retransmitting

                            if packetType == 'CON':
                                # reset the packet ID
                                packetID = 0
                                # if we get some message with an ACK in it, we will treat it as data
                                ackFlag = 1
                                break

                            if packetType == 'FIN':
                                # if the ground wants to terminate the transmission, this will trigger an end handshake
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
                            while i < len(missingPackets):
                                # take byte number i, convert it to binary of type str in format
                                # format takes the integer converts it to binary, 
                                missingPacketsBin = missingPacketsBin + format(int(missingPackets[i]), '08b')
                                # now we increase the counter
                                i += 1
                            
                            i = 0
                            while i < len(missingPacketsBin):
                                if missingPacketsBin[i] == '1':
                                    # send the missing packets
                                    payload = packetSentBuff[i]
                                    # if the first frame and ACK is missing we must retransmit it by itself to port 0
                                    if payload[0:3].decode('ascii') == 'ACK' and ackFlag == 0:
                                        packetID = 0
                                        sendPacket(IP_address_dst, IP_address_src, packetID, 'DAT', payload, 0)

                                    else:  #otherwise it's just data
                                            packetID = i
                                            sendPacket(IP_address_dst, IP_address_src, packetID, 'DAT', payload, reqPort)
                                i+=1
                                        # after this go back to the SYN
                            # we either get a MIS request or a CON request


                while True:
                   # send FIN
                   # if we have sent the total size of the object we land here
                   # FIN has null payload
                    payload = '0'
                    payload = payload.encode('ascii')
                    sendPacket(IP_address_dst, IP_address_src, 255, 'FIN', payload, 0)

                    # listen for MIS packet
                    packetRcvd = s.recvfrom(readLen)
                    # again get rid of IP header stuff
                    packetRcvd = packetRcvd[0]
                    # port byte is going to be zero 
                    # TODO write a check to make sure that the ports are zero
                    portByte   = format(int(packetRcvd[20]),'02x')
                    # checksum for integrity
                    checksum   = packetRcvd[21:23]
                    # packet type is by default 255
                    packetID   = packetRcvd[23]
                    # payload of MIS is 32 bytes
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
                            # send the missing packets
                            payload = packetSentBuff[i]
                            # if the first frame and ACK is missing we must retransmit it by itself to port 0
                            if payload[0:3].decode('ascii') == 'ACK' and ackFlag == 0:
                                packetID = 0
                                sendPacket(IP_address_dst, IP_address_src, packetID, 'DAT', payload, 0)

                            else:  #otherwise send all of thedata       
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


