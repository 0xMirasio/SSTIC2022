from numpy import full
import serial
import sys
import binascii
import signal
import sys
import os
import subprocess
import crypt


K1 = 12484484684683
K2 = 46884684656
os.environ["GOODFS_PASSWD"] = "goodfspassword"



ser = serial.Serial("/tmp/simavr-uart0")

"""
ser.write(b"\x03" + b"\x01" +b"A"*7 +b"\x00"*8)

R = binascii.hexlify(ser.read(8)).decode()
R2 = crypt.sign64(b"\x01" +b"A"*7 , b"\x00"*8,K1,K2)

try:
    assert(R == R2)
    print(f"ALL OK sign64(p1,p2) = {R}")

except AssertionError:
    print(f"Calculated output is not arduino output : {R} =! {R2}")
"""
#TEST----------------------------------------------------------------------

ser.write(b"\x03" + b"\x01" + b"anon" + b"\x00" * 3 + b"\x00"*8)

R = binascii.hexlify(ser.read(8)).decode()
R2 = crypt.sign64(b"\x01" + b"anon" + b"\x00" * 3 , b"\x00"*8,K1,K2)


try:
    assert(R == R2)
    print(f"ALL OK sign64(p1,p2) = {R}")

except AssertionError:
    print(f"Calculated output is not arduino output : {R} =! {R2}")


#--------------------------------------------------------------------------------
print("\n\n")
ser.write(b"\x03" + b"\x01" + b"anonymo" + b"\x00"*8)


R3 = binascii.hexlify(ser.read(8)).decode()
R2 = crypt.sign64(b"\x01" + b"anonymo" , b"\x00"*8,K1,K2)

try:
    assert(R3 == R2)
    print(f"ALL OK sign64(p1,p2) = {R3}")

except AssertionError:
    print(f"Calculated output is not arduino output : {R} =! {R2}")


print("\n\n")
#--------------------------------------------------------------------------------
from pwn import *
Rb = binascii.unhexlify(R)
R3b = binascii.unhexlify(R3)
print(f"{R} ^ {R3} = {binascii.hexlify(xor(Rb,R3b)).decode()}")

