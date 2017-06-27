#developed in python 3.5
import socket


# set IP address of source machine for sending, and dummy port (just filler)

CUDP_IP = "0.0.0.0"
CUDP_PORT = 0

# set the length of max read (e.g. cadet can only send 77 bytes at a time)
readLen = 77

# create a raw socket that will bind to the network interface, this will receive all raw packets at the OSI layer 3
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

try:
    s.bind((CUDP_IP,CUDP_PORT))
except:
    print ('ERROR BINDING')
    sys.exit()

# *******************************
# *******************************
# Begin listening logic
# *******************************
# *******************************

while True:
    # recieve the packet (77 bytes)
    packetRcvd = s.recvfrom(77)
    packetRcvd = packetRcvd[0]

    # should be 77 or less
    print(len(packetRcvd))
    # this includes the IP header of 20 bytes.

    # used to convert from bytes to ascii 
    # print((packetRcvd[29:]).decode('ascii'))

    # get the first byte of the payload (byte #20) this it the dst port/src port
    print(packetRcvd[24:])

    

