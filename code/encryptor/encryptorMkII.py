import struct


# # *********************************************************************************************************************
# # Packing to bytes because len of int = 4 bytes, len of char = 1 byte
# # *********************************************************************************************************************

# # Length of message
# messageLen = len(message)

# packedEncryptedMsg = struct.pack("{0:d}B".format(messageLen), *encryptedMsg)



def encryptMessage(message, pad, encryptedMsg):
	# *********************************************************************************************************************
	# Encrypt the message and print it to console for verification
	# *********************************************************************************************************************

	for m,p in zip(message,pad):
		cipher = (ord(m)^ord(p))
		encryptedMsg.append(cipher)
	print(encryptedMsg)
	return

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
	print(encryptedMsgRead)
	return encryptedMsgRead

def unpackMessage(packedEncryptedMsg):
	messageLen = len(packedEncryptedMsg)
	unpackedencryptedMessage = struct.unpack("{0:d}B".format(messageLen), packedEncryptedMsg)
	return unpackedencryptedMessage

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
	encryptMessage(message,pad,encryptedMsg)

	# pack the message
	packedEncryptedMsg = packMessage(encryptedMsg)

	# write packed message to file
	writePackedMsg(packedEncryptedMsg)

	# read packed message from file
	encryptedMsgRead = readPackedMsg()

	# unpack message read
	unpackedencryptedMessage = unpackMessage(encryptedMsgRead)









	print('*'*40)

	# CHECK TO SEE IF FUNCTION CHANGED STUFF
	print('encryptedMsg: ', encryptedMsg)
	print('*'*40)
	print('packedEncryptedMsg :', packedEncryptedMsg)
	print('*'*40)
	print('encryptedMessageRead :', encryptedMsgRead)
	print('*'*40)
	print('unpackedencryptedMessage :', unpackedencryptedMessage)
	print('*'*40)
	print('*'*40)



if __name__ == '__main__':
	main()



