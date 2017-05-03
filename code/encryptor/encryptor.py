import struct


string = '\x00abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()\x00.,'
padlong = 111111111111111111111111111111111111111111111111111111111111111111111111111111

message = list(string)
pad = list(str(padlong))

pad[0] = '?'

print(pad[0])
# message = ['}','B','B','B','B','B','B','B','B','B']
# pad = ['}','1','1','1','1','1','1','1','1','1']
encryptedMessage = []
decryptedMessage = []
encryptedMessageRcvd = []

for m,p in zip(message,pad):
	cipher = (ord(m)^ord(p))
	encryptedMessage.append(cipher)
print(encryptedMessage)

messageLen = len(encryptedMessage)

packedencryptedMessage = struct.pack("{0:d}B".format(messageLen), *encryptedMessage)

print(packedencryptedMessage)
print('\n')

unpackedencryptedMessage = struct.unpack("{0:d}B".format(messageLen), packedencryptedMessage)


encryptedMessageRcvd = list(unpackedencryptedMessage)



print(unpackedencryptedMessage)


if (list(unpackedencryptedMessage) == encryptedMessage):
	print('it works')

else:
	print('does not work')


f = open('cipher.txt','wb')
# encryptedMessage = bytes(encryptedMessage)
f.write(packedencryptedMessage)
f.close

# f = open('cipher.txt','rb')
# encryptedMessageRcvd = f.read()
# print(encryptedMessageRcvd)



# while byte !='\x00':
# 	byteRead = ord(byte)
# 	encryptedMessageRcvd.append(byteRead)
# 	byte = f.read(1)

 

for e,p in zip(encryptedMessageRcvd,pad):
	# e = binascii.b2a_base64(e)
	plaintext = chr(e^ord(p))
	decryptedMessage.append(plaintext)
print(decryptedMessage)



# >>> struct.unpack("{0:d}i".format(numelements),buf)

# >>> struct.pack("{0:d}i".format(numelements), *data)
