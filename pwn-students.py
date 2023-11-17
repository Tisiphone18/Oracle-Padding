import binascii
import socket
import telnetlib

# First take a look at the server. Afterwards, comment out the next four lines...
#t = telnetlib.Telnet("itsec.sec.in.tum.de", 7023)
#t.interact()
#import sys
#sys.exit(0)

# If you have done that, copy over a hexlified message + IV over to this script (replacing the zeros)
#iv = binascii.unhexlify("bb71a5e153c804c706da429e1f6fbf09")
iv = binascii.unhexlify("0e43344321d3d4eeca4e2ce0289164c8")
#msg = binascii.unhexlify("2c23ec9b2d8aa6ba4ee3bfc65fa40031023c7b8acf4b79eb0896f1be7e339484adac12f35ccf7db364044e6f0718bc65db5f5b72e413757a3192e4c385fddee8")
msg = binascii.unhexlify("321d0dfe901b992095a77520e1fca89aab477d76197237d04a70bc2dcca56a45268bff786cc56261485f51c68b16ccdd82381358911298ed67ce9613cb3f3979")
print(msg)

block_size = 16
blocks = [msg[i:i+block_size] for i in range(0, len(msg), block_size)]

zwischen_block = [bytes([0 & 0xFF]),bytes([0 & 0xFF]),bytes([0 & 0xFF]),bytes([0 & 0xFF])]
def read_until(s, token):
    """Reads from socket `s` until a string `token` is found in the response of the server"""
    buf = b""
    while True:
        data = s.recv(2048)
        buf += data
        if not data or token in buf:
            return buf

# The server allows you to process a single message with each connection.
# Connect multiple times to decrypt the (IV, msg) pair above byte by byte.#

#try for last char:#
'''

found = 0
for i in range(0,256):
    s = socket.socket()
    s.connect(("itsec.sec.in.tum.de", 7023))

    i_hex = i.to_bytes(1, byteorder='big')
    msg_temp = blocks[0] + blocks[1] + blocks[2][:-1] + i_hex + blocks[3]
    start = read_until(s, b"Do you")

    s.send(binascii.hexlify(iv) + b"\n")
    s.send(binascii.hexlify(msg_temp) + b"\n")

    response = read_until(s, b"\n")

    if b'OK' in response:
        print(i)
        found = i_hex
        break
        #todo remove break
print(found)

stelle = bytes([0x01 & 0xFF])
xor = bytes(x ^ y for x, y in zip(found, stelle))

zwischen_block[2] = str(xor) + zwischen_block[2]

print(xor)
print(zwischen_block)

x = bytes([0x02 & 0xFF])
x = bytes(x ^ y for x, y in zip(xor, x))

found = 0
for i in range(0,256):
    s = socket.socket()
    s.connect(("itsec.sec.in.tum.de", 7023))

    i_hex = i.to_bytes(1, byteorder='big')
    msg_temp = blocks[0] + blocks[1] + blocks[2][:-2] + i_hex + x + blocks[3]
    start = read_until(s, b"Do you")

    s.send(binascii.hexlify(iv) + b"\n")
    s.send(binascii.hexlify(msg_temp) + b"\n")

    response = read_until(s, b"\n")

    if b'OK' in response:
        print(i)
        found = i_hex
        break
        #todo remove break
print(found)

stelle = bytes([0x02 & 0xFF])
xor = bytes(x ^ y for x, y in zip(found, stelle))

zwischen_block[2] = str(xor) + zwischen_block[2]

print(xor)
print(zwischen_block)
'''
found = 0
paddings = [0x02, 0x0303, 0x040404, 0x05050505, 0x0606060606, 0x070707070707, 0x08080808080808, 0x0909090909090909, 0x0a0a0a0a0a0a0a0a0a,0x0b0b0b0b0b0b0b0b0b0b,0x0c0c0c0c0c0c0c0c0c0c0c,0x0d0d0d0d0d0d0d0d0d0d0d0d0d, 0x0e0e0e0e0e0e0e0e0e0e0e0e0e,0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f] #paddings : 2 33 444



#for the last block
for byte_nr in range(1, 17):

    print("Checking the byte number:", byte_nr)
    found = bytes([0 & 0xFF])
    x = bytes([0 & 0xFF])
    msg_temp = 0

    for i in range(0, 256):
        s = socket.socket()
        s.connect(("itsec.sec.in.tum.de", 7023))

        if byte_nr == 1:
            msg_temp = blocks[0] + blocks[1] + blocks[2][:-1] + i.to_bytes(1, byteorder='big') + blocks[3]
        else:
            msg_temp = blocks[0] + blocks[1] + blocks[2][:-(i + 1)] + i.to_bytes(1, byteorder='big') + x + blocks[3]

        start = read_until(s, b"Do you")

        s.send(binascii.hexlify(iv) + b"\n")
        s.send(binascii.hexlify(msg_temp) + b"\n")

        response = read_until(s, b"\n")

        if b'OK' in response:
            found = i.to_bytes(1, byteorder='big') # -> a2
            print("Found after:", i)
            print(found)
            break # todo remove break

    stelle = bytes([byte_nr & 0xFF])
    xor = bytes(x ^ y for x, y in zip(found, stelle)) # -> a0

    print("Zwischenblock: ", zwischen_block)
    print("xor: ", xor)
    if byte_nr == 1:
        zwischen_block[3] = xor
    else:
        zwischen_block[3] = xor + zwischen_block[3]
    print(paddings[byte_nr-1])
    x = paddings[byte_nr-1].to_bytes(byte_nr, byteorder='big')
    x = bytes(x ^ y for x, y in zip(xor, x))

    print("Ready for next round")


#for i in range(len(msg)):
#    s = socket.socket()
 #   s.connect(("itsec.sec.in.tum.de", 7023))
#
 #   start = read_until(s, b"Do you")
  #  ########################################
   # # Implement padding oracle attack here #
    #########################################
#
 #   s.send(binascii.hexlify(iv) + b"\n")
  #  s.send(binascii.hexlify(msg) + b"\n")

   # response = read_until(s, b"\n")
    #print(response)


