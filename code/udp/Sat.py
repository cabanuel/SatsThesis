#developed in python 3.5
import socket
import os
from  struct import *

# set IP address of source machine for sending, and dummy port (just filler)

CUDP_IP = "0.0.0.0"
CUDP_PORT = 0

IP_address_src = '192.168.1.3'
IP_address_dst = '192.168.1.2'
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
        data = packetType.encode('ascii') + reqPortByte + payload # REQ (3 bytes), payload = REQUESTED PORT+object
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

    if packetType == 'FIN':
        data = packetType.encode('ascii') + payload #empty payload
        srcport = 0
        dstport = 0
        portByte = (srcport<<4)+dstport

        checksum = 0 # TODO: write a function to calculate checksum of payload
        udp_header = pack('!BHB', portByte, checksum, packetID)
        s.sendto(ip_header+udp_header+data, (IP_address_dst, dstport));

    if packetType == 'SYN':
        data = packetType.encode('ascii') + payload #payload = SYN, NULL 
        srcport = 0
        dstport = reqPort
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
        srcport = 2 
        dstport = reqPort
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
                objReqSize = hex(os.stat(objReq).st_size) # length of object requested in hex (to save space)
                objReqSize = objReqSize[2:] #take the length in hex
                objReqSize = objReqSize.zfill(5) #pad to 5 spaces

                paddedOTPOffset = hex(OTP_OFFSET)
                paddedOTPOffset = paddedOTPOffset[2:]
                paddedOTPOffset = paddedOTPOffset.zfill(5) # need to pad to 5 total bytes
                
                payload = (paddedOTPOffset + objReqSize).encode('ascii') 
                print('*SENDING ACK*')
                sendPacket(IP_address_dst, IP_address_src, 0, 'ACK', payload, reqPort)

                # TIME TO SEND DATA
                dataSent = 0
                packetID = 0
                f = open(objReq, 'rb')
                # data sent dictionary
                packetSentBuff = {}
                packetSentBuff[packetID] = payload
                packetID +=1 
                print('*SENDING DATA*')
                while dataSent < objReqSizeDec:
                    if packetID < 255:
                        payload = f.read(53)
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
                            sendPacket(IP_address_dst, IP_address_src, 255, 'SYN', payload, reqPort)
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

                            # first we check that we didnt get a CONtinue message. if CON we are done retransmitting

                            if packetType == 'CON':
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

                            # set up index for packets
                            i = 0
                            missingPacketsBin = ''
                            while i < len(missingPackets):
                                # take byte number i, convert it to binary of type str in format
                                # format takes the integer converts it to binary, 
                                missingPacketsBin = missingPacketsBin + format(missingPackets[i], '08b')
                                # now we increase the counter
                                i += 1
                            # after getting the 32 bytes, and convering them to binary, we iterate over
                            # the string treating the index as the index for packet. if i == 1, then 
                            # we go back to the dictionary and retransmit. if packets retransmitted ==0
                            # we set packetID = 0, purge the dictionary, and send the next 255 packets 
                            # of data



                            while i < len(missingPacketsBin):
                                if missingPacketsBin[i] == 1:
                                    payload = packetSentBuff[1]
                                    packetID = i
                                    sendPacket(IP_address_dst, IP_address_src, packetID, 'DAT', payload, reqPort)
                            # after this go back to the SYN
                            # we either get a MIS request or a CON request




                while True:
                   # send FIN
                    # print(packetSentBuff)
                    payload = '0'
                    payload = payload.encode('ascii')
                    sendPacket(IP_address_dst, IP_address_src, 255, 'FIN', payload, reqPort)

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

                    print('missingpacketsbin ', type(missingPacketsBin))
                    i = 0
                    while i < len(missingPacketsBin):
                        if missingPacketsBin[i] == '1':
                            payload = packetSentBuff[i]
                            packetID = i
                            sendPacket(IP_address_dst, IP_address_src, packetID, 'DAT', payload, reqPort)
                        i+=1
                    # after this go back to the SYN
                    # we either get a MIS request or a CON request




                        # payload = f.read(53)
                        # packetSentBuff[packetID] = payload
                        # sendPacket(IP_address_dst, IP_address_src, packetID, 'DAT', payload, reqPort)
                        # dataSent += 53
                        # packetID += 1
                    # send SYN
                print(packetSentBuff)
                # payload = '0'
                # payload = payload.encode('ascii')
                # print('*SENDING FIN*')
                # sendPacket(IP_address_dst, IP_address_src, 255, 'FIN', payload, reqPort)




                




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

