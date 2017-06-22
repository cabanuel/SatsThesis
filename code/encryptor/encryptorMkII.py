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
	# Encrypt the message converting the values into int and XORing them
	# *********************************************************************************************************************
	encryptedMsg =[]
	for m,p in zip(message,pad):
		cipher = (ord(m)^ord(p))
		encryptedMsg.append(cipher)
	# print('inside encrypt func: ',encryptedMsg)
	return encryptedMsg

def packMessage(encryptedMsg):
	# *********************************************************************************************************************
	# Gotta pack the message, because python likes ints to be 4 bytes, while C and everyone else likes 1 byte per char
	# *********************************************************************************************************************
	messageLen = len(encryptedMsg)
	packedEncryptedMsg = struct.pack("{0:d}B".format(messageLen), *encryptedMsg)
	return packedEncryptedMsg

def writePackedMsg(packedEncryptedMsg):
	# *********************************************************************************************************************
	# Write the packed message out to a file (will be later used to send over network)
	# *********************************************************************************************************************
	f = open('cipher.txt','wb')
	# encryptedMessage = bytes(encryptedMessage)
	f.write(packedEncryptedMsg)
	f.close()
	return

def readPackedMsg():
	# *********************************************************************************************************************
	# open file, read message 
	# *********************************************************************************************************************
	f = open('cipher.txt','rb')
	encryptedMsgRead = f.read()
	f.close()
	return encryptedMsgRead

def unpackMessage(packedEncryptedMsg):
	# *********************************************************************************************************************
	# unpack to use with python again
	# *********************************************************************************************************************
	messageLen = len(packedEncryptedMsg)
	unpackedencryptedMessage = struct.unpack("{0:d}B".format(messageLen), packedEncryptedMsg)
	return unpackedencryptedMessage

def unpack_ParseMessage(encryptedMsgRead):
	# *********************************************************************************************************************
	# gotta make it into a list to be able to play with it
	# *********************************************************************************************************************
	unpackedencryptedMessage = unpackMessage(encryptedMsgRead)
	unpackedencryptedMessageList = list(unpackedencryptedMessage)
	return unpackedencryptedMessageList

def decryptMessage(unpackedencryptedMessageList,pad):
	# *********************************************************************************************************************
	# same as encrypt
	# *********************************************************************************************************************
	decryptedMessage = []
	for e,p in zip(unpackedencryptedMessageList,pad):
		clearText = chr(e ^ ord(p))
		decryptedMessage.append(clearText)
	return decryptedMessage

def bitFlipper(encryptedMsgRead):
	# *********************************************************************************************************************
	# Take random bits and flip them with a discrete probability. Used to measure error propagation in simulation
	# *********************************************************************************************************************
	# convert the packed, encrypted message into bits and make it a list
	binaryMsg =  bin(int.from_bytes(encryptedMsgRead, 'big'))
	binaryMsgList = list(binaryMsg)
	# print('Binary MSG LIst: ', binaryMsgList)
	print('Binary MSG before flip: ', binaryMsg)
	
	# Based on a probability, we can establish the probability of each bit getting flipped

	# 0 for no change, 1 flips the bit
	elements = [0,1]
	# 1/16 bits needs to be flipped. so probability of flipping is 0.0625
	probabilities = [0.9375, 0.0625]

	# need to keep count of bits flipped for later analysis
	bitsFlipped = 0

	# need to skip the 0, and 1st bit since they  are there for python reasons
	for i in range(2, len(binaryMsgList)):
		# get a random probability (labeled coin for coin toss though probabilities can be changed)
		coinList = (numpy.random.choice(elements,1,p=list(probabilities))).tolist()
		coin = coinList[0]
		# if the coin is 0 then go back to the top, and increase i
		if coin == 0:
			continue
		# else the coin is not zero, so we have to change 0 -> 1, and 1 ->0 in position i of binaryMsgList 
		if 	binaryMsgList[i] == '0':
			binaryMsgList[i] = '1'
			bitsFlipped += 1
			continue
		if  binaryMsgList[i] == '1':
			binaryMsgList[i] = '0'
			bitsFlipped += 1
			
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

	# return the encrypted packed message with some bits flipped and the counter. 
	return encryptedMsgReadFlipped, bitsFlipped

def flipSubroutine(i,binaryMsgList):
	if 	binaryMsgList[i] == '0':
		binaryMsgList[i] = '1'
	else:
		binaryMsgList[i] = '0'
	return binaryMsgList[i]

def tripletBitFlipper(encryptedMsgRead):
	# *********************************************************************************************************************
	# Take random bits and flip them with a discrete probability. Used to measure error propagation in simulation
	# *********************************************************************************************************************
	# convert the packed, encrypted message into bits and make it a list
	binaryMsg =  bin(int.from_bytes(encryptedMsgRead, 'big'))
	binaryMsgList = list(binaryMsg)
	# print('Binary MSG LIst: ', binaryMsgList)
	print('Binary MSG before flip: ', binaryMsg)
	
	# Based on a probability, we can establish the probability of a bit getting flipped

	# 0 for no change, 1 flips the bit
	elements = [0,1]
	# 1/16 bits needs to be flipped. so probability of flipping is 0.0625
	probabilities = [0.9375, 0.0625]

	# need to keep count of bits flipped for later analysis
	bitsFlipped = 0

	# initialize index of the list to 2 
	# need to skip the 0, and 1st bit since they  are there for python reasons ('0' and 'b')
	# thats why we start at 2
	i = 2


	while (i < len(binaryMsgList)):
		# get a random probability (labeled coin for coin toss though probabilities can be changed)
		coinList = (numpy.random.choice(elements,1,p=list(probabilities))).tolist()
		coin = coinList[0]
		# if the coin is 0 then go back to the top, and increase i
		if coin == 0:
			i+=1
			continue
		# else the coin is not zero, so we have to change 0 -> 1, and 1 ->0 in position i of binaryMsgList 
		else:
			# flip the first bit at position i
			binaryMsgList[i] = flipSubroutine(i,binaryMsgList)
			# increase thindex to i+1
			i+=1
			bitsFlipped+=1
			# if i+1 < EOF then we flip it and increase i to i+2
			if (i< len(binaryMsgList)):
				binaryMsgList[i] = flipSubroutine(i,binaryMsgList)
				i+=1
				bitsFlipped+=1
			# if i+1 suceeded in flipping, then we test if i+2 < EOF, if not then we are done and go back to while loop which will exit
			# if i+1 failed then this will also fail and we will go back to the top of the while loop
			if (i< len(binaryMsgList)):
				binaryMsgList[i] = flipSubroutine(i,binaryMsgList)
				i+=1
				bitsFlipped+=1
	


		# if 	binaryMsgList[i] == '0':
		# 	binaryMsgList[i] = '1'
		# 	bitsFlipped += 1
		# 	continue
		# if  binaryMsgList[i] == '1':
		# 	binaryMsgList[i] = '0'
		# 	bitsFlipped += 1
			
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

	# return the encrypted packed message with some bits flipped and the counter. 
	return encryptedMsgReadFlipped, bitsFlipped
	



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
	encryptedMsgReadFlipped, bitsFlipped = tripletBitFlipper(encryptedMsgRead)

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
	print('*'*40)
	print('bits flipped :')
	print(bitsFlipped)


if __name__ == '__main__':
	main()



