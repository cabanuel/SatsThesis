import struct
import binascii

# # *********************************************************************************************************************
# # Packing to bytes because len of int = 4 bytes, len of char = 1 byte
# # *********************************************************************************************************************

# # Length of message
# messageLen = len(message)

# packedEncryptedMsg = struct.pack("{0:d}B".format(messageLen), *encryptedMsg)



def encryptMessage(message, pad):
	# *********************************************************************************************************************
	# Encrypt the message and print it to console for verification
	# *********************************************************************************************************************
	encryptedMsg =[]
	for m,p in zip(message,pad):
		cipher = (ord(m)^ord(p))
		encryptedMsg.append(cipher)
	# print('inside encrypt func: ',encryptedMsg)
	return encryptedMsg

def packMessage(encryptedMsg):
	messageLen = len(encryptedMsg)
	packedEncryptedMsg = struct.pack("{0:d}B".format(messageLen), *encryptedMsg)
	return packedEncryptedMsg

def writePackedMsg(packedEncryptedMsg):
	f = open('cipher.txt','wb')
	# encryptedMessage = bytes(encryptedMessage)
	f.write(packedEncryptedMsg)
	f.close()
	return

def readPackedMsg():
	f = open('cipher.txt','rb')
	encryptedMsgRead = f.read()
	f.close()
	return encryptedMsgRead

def unpackMessage(packedEncryptedMsg):
	messageLen = len(packedEncryptedMsg)
	unpackedencryptedMessage = struct.unpack("{0:d}B".format(messageLen), packedEncryptedMsg)
	return unpackedencryptedMessage

def unpack_ParseMessage(encryptedMsgRead):
	unpackedencryptedMessage = unpackMessage(encryptedMsgRead)
	unpackedencryptedMessageList = list(unpackedencryptedMessage)
	return unpackedencryptedMessageList

def decryptMessage(unpackedencryptedMessageList,pad):
	decryptedMessage = []
	for e,p in zip(unpackedencryptedMessageList,pad):
		clearText = chr(e ^ ord(p))
		decryptedMessage.append(clearText)
	return decryptedMessage






def main():
	# *********************************************************************************************************************
	# Set up messages needed to encrypt and the OTP
	# Make them lists of one byte of 'str'
	# *********************************************************************************************************************

	# Set up the data string we want to encrypt
	# Set up the raw pad
	string = '\x00abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()\x00.,'
	padlong = 111111111111111111111111111111111111111111111111111111111111111111111111111111

	# TODO: Instead of hardcoding these, work on reading them from a file.


	# make each byte on the string it's own item in a list of type 'str'
	message = list(string)
	# make each byte on the string it's own item in a list of type 'str'
	pad = list(str(padlong)) 

	# *********************************************************************************************************************
	# set up some of the arrays used
	# *********************************************************************************************************************

	encryptedMsg = []
	decryptedMsg = []
	encryptedMsgRcvd = []

	# encrypt message
	encryptedMsg = encryptMessage(message,pad)

	# pack the message
	packedEncryptedMsg = packMessage(encryptedMsg)

	# write packed message to file
	writePackedMsg(packedEncryptedMsg)

	# read packed message from file
	encryptedMsgRead = readPackedMsg()
	print('Before errors introduced: ',encryptedMsgRead)

	# unpack message read
	encryptedMsgRcvd = unpack_ParseMessage(encryptedMsgRead)

	# decrypt the message
	decryptedMsg = decryptMessage(encryptedMsgRcvd, pad)


# next thing is take a byte and do a random number mod 8, set that to be the poistion on binary string and convert
# it to array of 0s and 1s. If the element is a 0, conver to 1, and vice versa. add logic to randomly change things to burst
# add logic for only  single bit change, and add logic for combo


	print('*'*40)

	# CHECK TO SEE IF FUNCTION CHANGED STUFF
	print('encryptedMsg: ', encryptedMsg)
	print('*'*40)
	print('packedEncryptedMsg :', packedEncryptedMsg)
	print('*'*40)
	print('encryptedMessageRead :', encryptedMsgRead)
	print('*'*40)
	print('encryptedMsgRcvd :', encryptedMsgRcvd)
	print('*'*40)
	print('decryptedMessage :', decryptedMsg)
	print('*'*40)



if __name__ == '__main__':
	main()



