from struct import *
x = "00000001"
y = "00000010"
z = x+y

i = 0
missingpack = []
while i < 2:
	missingpack.append( int(z[i*8:i*8+8],2))
	i +=1



payload = pack('!BB', missingpack[0],
 missingpack[1])

print(payload)


for i in range(1,32):
	print(i)