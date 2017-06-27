'''
    Raw sockets on Linux
     
    Silver Moon (m00n.silv3r@gmail.com)
'''
 
# some imports
import socket, sys
from struct import *
 
# checksum functions needed for calculation checksum
def checksum(msg):
    s = 0
     
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        s = s + w
     
    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);
     
    #complement and mask to 4 byte short
    s = ~s & 0xffff
     
    return s
 
#create a raw socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
except:
    print( 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()
 
# tell kernel not to put in headers, since we are providing it, when using IPPROTO_RAW this is not necessary
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
     
# now start constructing the packet
packet = '';
 
source_ip = '192.168.1.2'
dest_ip = '192.168.1.3' # or socket.gethostbyname('www.google.com')
 
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
 
# # tcp header fields
# tcp_source = 1234   # source port
# tcp_dest = 80   # destination port
# tcp_seq = 454
# tcp_ack_seq = 0
# tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
# #tcp flags
# tcp_fin = 0
# tcp_syn = 1
# tcp_rst = 0
# tcp_psh = 0
# tcp_ack = 0
# tcp_urg = 0
# tcp_window = socket.htons (5840)    #   maximum allowed window size
# tcp_check = 0
# tcp_urg_ptr = 0
 
# tcp_offset_res = (tcp_doff << 4) + 0
# tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
 
# # the ! in the pack format string means network order
# tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)
 
# user_data = 'Hello, how are you'
 
# # pseudo header fields
# source_address = socket.inet_aton( source_ip )
# dest_address = socket.inet_aton(dest_ip)
# placeholder = 0
# protocol = socket.IPPROTO_TCP
# tcp_length = len(tcp_header) + len(user_data)
 
# psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
# psh = psh + tcp_header + user_data;
 
# tcp_check = checksum(psh)
# #print tcp_checksum
 
# # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
# tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)
 
# # final full packet - syn packets dont have any data
# packet = ip_header + tcp_header + user_data

# s = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)




data1 = 'string'
data2 = 12
data = data1.encode('ascii') + str(data2).encode('ascii') 
# sport = 4711    # arbitrary source port
# dport = 9001   # arbitrary destination port
dstport = 2
srcport = 1
portByte = (srcport<<4)+dstport
# length = 8+len(data);
checksum = 0
packetID = 17
# udp_header = pack('!HHHHB', sport, dport, length, checksum, packetID)
udp_header = pack('!BHB', portByte, checksum, packetID)
s.sendto(ip_header+udp_header+data, ('192.168.1.3', dstport));




 
# #Send the packet finally - the port specified has no effect
# s.sendto(packet, (dest_ip , 0 ))    # put this in a loop if you want to flood the target







# i = int(s,16)

# # s = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)
# data = 'string'
# sport = 4711    # arbitrary source port
# dport = 9001   # arbitrary destination port
# length = 12+len(data);
# checksum = 0
# packetID = 1
# udp_header = struct.pack('!HHHHH', sport, dport, length, checksum, packetID)
# s.sendto(ip_header+udp_header+data, ('192.168.1.3', dport));

























# from socket import *
# import struct

# s = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)
# data = 'string'
# sport = 4711    # arbitrary source port
# dport = 9001   # arbitrary destination port
# length = 12+len(data);
# checksum = 0
# packetID = 1
# udp_header = struct.pack('!HHHHH', sport, dport, length, checksum, packetID)
# s.sendto(udp_header+data, ('192.168.1.3', dport));


















# import socket

# UDP_IP = "192.168.1.3"
# UDP_PORT = 9001
# MESSAGE = "Hello, World!"

# print("UDP target IP:", UDP_IP)
# print("UDP target port:", UDP_PORT)
# print("message:", MESSAGE)

# sock = socket.socket(socket.AF_INET, # Internet
#                      socket.SOCK_DGRAM) # UDP
# sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))