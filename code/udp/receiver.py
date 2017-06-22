# import socket

UDP_IP = "0.0.0.0"
UDP_PORT = 9001

# sock = socket.socket(socket.AF_INET, # Internet
#                      socket.SOCK_DGRAM) # UDP
# sock.bind((UDP_IP, UDP_PORT))

# while True:
#     data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
#     print "received message:", data


import socket

# the public network interface
# HOST = socket.gethostbyname(socket.gethostname())

# create a raw socket and bind it to the public interface
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s.bind((UDP_IP, UDP_PORT))

# # Include IP headers
# s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# # receive all packages
# s.setsockopt(socket.SIO_RCVALL, socket.RCVALL_ON)

# receive a package
while True:
	print s.recvfrom(65565)

# # disabled promiscuous mode
# s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)