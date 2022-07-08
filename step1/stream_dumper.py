from audioop import add
import subprocess
import sys
import time

allfat= []
r = subprocess.check_output("olemap Recette.doc --fat", shell=True).decode().split("\n")
print("------------------------")
for i in range(10,len(r)-3):
    allfat.append(r[i])

pro = []
used = []

for fat in allfat:
    temp = fat.split("|")
    number = temp[1].replace(" ","")
    status = temp[2].replace(" ","")
    address = temp[3].replace(" ","")
    next_fat = temp[4].replace(" ","")
    pro.append([number, status, address, next_fat])


def get_bytecode(i):
    f= open("Recette.doc","rb")
    addr= int(pro[i][2],16)
    f.read(addr)
    bytecode = f.read(sector_size)
    f.close()
    return bytecode

bytecode_dic = {}
sector_size = 512


for i in range(len(pro)):
    bytecode = get_bytecode(i)
    bytecode_dic[i] = bytecode

for i in range(len(pro)):

    next= pro[i][3]
    next_int = int(next,16)

    while (next != "FFFFFFFE" and next != "FFFFFFFD" and next != "FFFFFFFF"):
        #print(i , next)
        if (next not in used):
            used.append(next)
        else:
            break
        next = pro[next_int][3]
        next_int = int(next,16)

        


for i in range(len(pro)):
    v= pro[i][0]
    if v not in used and pro[i][1] != "Free" and pro[i][1] !="FATSector" and pro[i][1] !="EndofChain" :
        print("stream complete: ", v)
        av = int(v,16)
        f = open("stream%d" % av, "wb")
        f.write(bytecode_dic[av])
        while (next != "FFFFFFFE" and next != "FFFFFFFD" and next != "FFFFFFFF"):
            
            next = pro[next_int][3]
            next_int = int(next,16)
            if (next != "FFFFFFFE" and next != "FFFFFFFD" and next != "FFFFFFFF"):
                f.write(bytecode_dic[next_int])

        f.close()