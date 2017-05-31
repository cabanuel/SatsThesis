import struct
import binascii
import numpy

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
	# *********************************************************************************************************************
	# Encrypt the message and print it to console for verification
	# *********************************************************************************************************************
	messageLen = len(encryptedMsg)
	packedEncryptedMsg = struct.pack("{0:d}B".format(messageLen), *encryptedMsg)
	return packedEncryptedMsg

def writePackedMsg(packedEncryptedMsg):
	# *********************************************************************************************************************
	# Encrypt the message and print it to console for verification
	# *********************************************************************************************************************
	f = open('cipher.txt','wb')
	# encryptedMessage = bytes(encryptedMessage)
	f.write(packedEncryptedMsg)
	f.close()
	return

def readPackedMsg():
	# *********************************************************************************************************************
	# Encrypt the message and print it to console for verification
	# *********************************************************************************************************************
	f = open('cipher.txt','rb')
	encryptedMsgRead = f.read()
	f.close()
	return encryptedMsgRead

def unpackMessage(packedEncryptedMsg):
	# *********************************************************************************************************************
	# Encrypt the message and print it to console for verification
	# *********************************************************************************************************************
	messageLen = len(packedEncryptedMsg)
	unpackedencryptedMessage = struct.unpack("{0:d}B".format(messageLen), packedEncryptedMsg)
	return unpackedencryptedMessage

def unpack_ParseMessage(encryptedMsgRead):
	# *********************************************************************************************************************
	# Encrypt the message and print it to console for verification
	# *********************************************************************************************************************
	unpackedencryptedMessage = unpackMessage(encryptedMsgRead)
	unpackedencryptedMessageList = list(unpackedencryptedMessage)
	return unpackedencryptedMessageList

def decryptMessage(unpackedencryptedMessageList,pad):
	# *********************************************************************************************************************
	# Encrypt the message and print it to console for verification
	# *********************************************************************************************************************
	decryptedMessage = []
	for e,p in zip(unpackedencryptedMessageList,pad):
		clearText = chr(e ^ ord(p))
		decryptedMessage.append(clearText)
	return decryptedMessage

def bitFlipper(encryptedMsgRead):
	# *********************************************************************************************************************
	# Encrypt the message and print it to console for verification
	# *********************************************************************************************************************
	binaryMsg =  bin(int.from_bytes(encryptedMsgRead, 'big'))
	binaryMsgList = list(binaryMsg)
	# print('Binary MSG LIst: ', binaryMsgList)
	print('Binary MSG before flip: ', binaryMsg)
	
	
	# 0 for no change, 1 flips the bit
	elements = [0,1]
	# 1/16 bits needs to be flipped. so probability of flipping is 0.0625
	probabilities = [0.9375, 0.0625]

	# need to skip the 0, and 1st bit since they  are there for python reasons

	for i in range(2, len(binaryMsgList)):
		# get a random probability (labled coin for coin toss though probabilities can be changed)
		coinList = (numpy.random.choice(elements,1,p=list(probabilities))).tolist()
		coin = coinList[0]
		# if the coin is 0 then go back to the top, and increase i
		if coin == 0:
			continue
		# else the coin is not zero, so we have to change 0 -> 1, and 1 ->0 in position i of binaryMsgList 
		if 	binaryMsgList[i] == '0':
			binaryMsgList[i] = '1'
			continue
		if  binaryMsgList[i] == '1':
			binaryMsgList[i] = '0'
			
	# after the bits have been flipped time to rejoin the list into a string
	binaryMsg = ''.join(binaryMsgList)
	print('binary MSG after flip: ', binaryMsg)

	# convert to ints for python because python loves ints
	binaryMsgInt = int(binaryMsg,2)

	# we then convert back to the packed char bytes that we had originally
	encryptedMsgReadFlipped = binascii.unhexlify('%x' % binaryMsgInt)

	# quick test
	# **************************************************
	print('No flip: ',encryptedMsgRead)
	print('Flip: ', encryptedMsgReadFlipped)
	if encryptedMsgReadFlipped == encryptedMsgRead:
		print('Same')
	else:
		print('Different')
	# **************************************************

	return encryptedMsgReadFlipped


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
	encryptedMsgReadFlipped = bitFlipper(encryptedMsgRead)

	# unpack message read
	encryptedMsgRcvd = unpack_ParseMessage(encryptedMsgRead)
	encryptedMsgRcvdFlipped = unpack_ParseMessage(encryptedMsgReadFlipped)
	# decrypt the message
	decryptedMsg = decryptMessage(encryptedMsgRcvd, pad)
	decryptedMsgFlipped = decryptMessage(encryptedMsgRcvdFlipped, pad)

	print('*'*40)

	# CHECK TO SEE IF FUNCTION CHANGED STUFF
	print('encryptedMsg: ')
	print(encryptedMsg)
	print('*'*40)
	print('packedEncryptedMsg :') 
	print(packedEncryptedMsg)
	print('*'*40)
	print('encryptedMessageRead :')
	print(encryptedMsgRead)
	print('*'*40)
	print('encryptedMsgRcvd :')
	print(encryptedMsgRcvd)
	print('*'*40)
	print('decryptedMessage :')
	print(decryptedMsg)
	print('*'*40)
	print('decryptedMessageFlipped : ')
	print(decryptedMsgFlipped)


if __name__ == '__main__':
	main()



