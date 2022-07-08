
import sys
import binascii
from pwn import *

import colorama
from colorama import Fore
from colorama import Style


"""

entry: p1 , p2 
saved : k1, k2
output : R

C1 = crypt(p1, k1)
C2 = C1 ^ p2
C3 = crypt(C2, k1)
C4 = C3 ^ k2
R = crypt(c4, k1)


"""


def Vec2Byte(c):
    r = b""
    for i in range(len(c)):
        r += bytes([c[i]])
    return r

def Int2Byte(i):
    r = binascii.unhexlify("{0:0{1}x}".format(i,16))
    if len(r) == 8:
        return r
    else:
        return b"\x00"*(8-len(r)) + r

def Reverse(b):
    r = b""
    for i in range(len(b)):
        r += bytes([b[len(b)-i-1]])
    return r
    

class Crypt():

    def __init__(self,p1,k1):
        self.k1 = k1
        self.A1 = 0xb7
        self.A2 = 0x3c
        self.A3 = 0xf4
        self.A4 = 0x47
        self.A5 = 0x02

        self.p1 = p1 

        self.p1a = [0]*8

        self.final_result = [0]*8 #r3,r4,r5,r5,y+1 -> y+4

        self.temp1 = [0]*8 #Z XH Y+5 Y+6 r8 r9 r7
        self.result = [0]*8 #r18-r25
        self.K = [0]*8 #r10:r15 r2 r17

        self.fill(self.p1a, self.p1)

        self.fillint(self.K, self.k1)




    def fill(self, a1 , v1):
        for i in range(8):
            a1[i] = v1[i]

    def fillint(self, a1 , i1):
        hi1 = "{0:0{1}x}".format(i1,16)
        for i in range(8):
            a1[i] = int(hi1[i*2:(i*2)+2],16)

        a1 = a1.reverse()

    def pprint(self):
        print("-----------------------")
        print(f"r10:r15 r2 r17 : T2 = {self.K}")
        print(f"r3,r4,r5,r5,y+1 -> y+4 => FR = {self.final_result}")
        print("-----------------------")

    def zero(self, a1):
        for i in range(8):
            if a1[i] != 0:
                return False
        return True

    def xorarray(self, a1, a2):
        for i in range(8):
            a1[i] = a1[i] ^ a2[i]

    def rotate_left(self, a1):
        a2 = [0]*8
        carry = 0 
        for i in range(8):
            t = a1[i] << 1
            if t > 0xff:
                if i ==0:
                    a2[i] = t % 256
                    
                else:
                    a2[i] = (t % 256) + carry
                    carry = 0
                carry = 1

            else:
                a2[i] = t + carry
                carry = 0

        return a2

    def rotate_right(self, a1):
        a2 = [0]*8
        carry = False
        for i in range(8):
            if (carry):
                a2[len(a1)-i-1] = (a1[len(a1)-i-1] >> 1) | 0x80
            else:
                a2[len(a1)-i-1] = a1[len(a1)-i-1] >> 1

            carry = bool(a1[len(a1)-i-1] & 1)
            

        return a2

    def test_exit(self, a1):
    
        carry = False
        gen = False
        for i in range(8):
            
            r=  bool(a1[i] & 0x80)
            gen = bool(r + carry)
            if (a1[i] == 0):
                gen = False
            if (r == True):
                carry = True
            else:
                carry = False
            
        if carry==False:
            gen = False
        return not(gen)

    def crypt(self):
        i=0
        self.temp1 = self.p1a
        while True:
            #print("Iteration ---> " , str(i))
            self.result = self.temp1
            if (self.zero(self.result)):
                break
            
            self.result = self.K
            if (self.zero(self.result)):
                break

            
            hk1_1 = self.result[0] & 1            

            if (hk1_1):
                self.xorarray(self.final_result, self.temp1)
            self.result = self.temp1

            hk1_1 = self.test_exit(self.result)
            #print("HK1_1 = ", hk1_1)
            if (hk1_1 == True):
                self.result = self.rotate_left(self.temp1)
                self.temp1 = self.result
                
            else:
                self.result = self.rotate_left(self.temp1)
                self.temp1[0] = self.result[0] ^ self.A1
                self.temp1[1] = self.result[1] ^ self.A2
                self.temp1[2] = self.result[2] ^ self.A3
                self.temp1[3] = self.result[3] ^ self.A4
                self.temp1[4] = self.result[4] ^ self.A5
            
            self.temp1[5] = self.result[5]
            self.temp1[6] = self.result[6]
            self.temp1[7] = self.result[7]
            
            self.result = self.rotate_right(self.K)
            self.K = self.result

            #self.pprint()
            i += 1


        #print("Done!")

def sign64(p1,p2,k1,k2):
    print(f"{Fore.RED}Calling Crypt() with p1 = {Fore.GREEN}{p1}, p2 = {p2}{Style.RESET_ALL}")
    hsm = Crypt(p1,k1)
    hsm.crypt()
    c1 = hsm.final_result
    c1f = Vec2Byte(c1)
    print(f"C1={Fore.BLUE}{binascii.hexlify(c1f).decode()} {Style.RESET_ALL}(crypt(P1, k1)")

    c11= xor(c1f, p2)

    print(f"C2={Fore.BLUE}{binascii.hexlify(c11).decode()} {Style.RESET_ALL}(XOR(C1, P2)")

    hsm = Crypt(c11,k1)
    hsm.crypt()
    c2 = hsm.final_result
    c2f = Vec2Byte(c2)
    print(f"C3={Fore.BLUE}{binascii.hexlify(c2f).decode()} {Style.RESET_ALL}(crypt(C2, K1)")


    K2b = Reverse(Int2Byte(k2))
    c3 = xor(c2, K2b)
    print(f"C4={Fore.BLUE}{binascii.hexlify(c3).decode()} {Style.RESET_ALL}(XOR(C3, K2)")


    hsm = Crypt(c3,k1)
    hsm.crypt()
    R = hsm.final_result
    Rb = Vec2Byte(R)
    print(f"R={Fore.GREEN}{binascii.hexlify(Rb).decode()} {Style.RESET_ALL}(crypt(C4,k1)")

    return binascii.hexlify(Rb).decode()



import sys
import binascii
from pwn import *

K1=12484484684683
K2=46884684656

print(f"Starting crypt.py with K1={K1} and K2={K2}")

DEBUG=True
if (DEBUG):
    p2 = b"B"*8
    p1 = b"A"*8

    p1 = b"\x01" + b"A"*7
    p2 = b"\x00"*8

    R = sign64(p1,p2, K1, K2)
    print(f"signu64({binascii.hexlify(p1).decode()},{binascii.hexlify(p2).decode()}) --> {R}")


