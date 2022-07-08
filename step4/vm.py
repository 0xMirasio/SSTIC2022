trace = open("trace.txt", "r")

trace = trace.read().replace("\t","").split("\n")
opcode = set()
for code in trace:
    args = code.split("  ")
    args_f = []
    for arg in args:
        if arg == '' or arg == ' ':
            pass
        else:
            args_f.append(arg)
    if "RDI=" in str(args_f):
        rdi = str(args_f).split("RDI=")[1][8:16]
        if rdi[0:4] == "0000" and rdi != "00000001" and rdi != "00000003" and rdi != "00000004"  and rdi != "00000005" and rdi != "00000020" and rdi != "00000100" and rdi != "00000000" :
            opcode.add(rdi[4:8])



start_addr = 0x0000555555555140
print(f"Total number of Virtual OPCODE : {len(opcode)}")
print(opcode)
fun = {}

for op in opcode:
    if op == "4CF5":
        fun[op] = [hex(start_addr + int(op,16)),"EXITVM"]
    elif op == "5727":
        fun[op] = [hex(start_addr + int(op,16)),"UH1"]
    elif op == "4C29":
        fun[op] = [hex(start_addr + int(op,16)),"MOV RX, [B2] ; PUSH RX"]
    elif op == "4327":
        fun[op] = [hex(start_addr + int(op,16)),"MOV R1,[B1] ; PUSH R1"]
    elif op == "2E59":
        fun[op] = [hex(start_addr + int(op,16)),"UH4"]
    elif op == "4EE7":
        fun[op] = [hex(start_addr + int(op,16)),"UH5"]
    elif op == "67B8":
        fun[op] = [hex(start_addr + int(op,16)),"MOV R1,[B1] ; "]
    elif op == "5444":
        fun[op] = [hex(start_addr + int(op,16)),"UH7"]
    elif op == "68C5":
        fun[op] = [hex(start_addr + int(op,16)),"START_FUN(R1)"]
    elif op == "5299":
        fun[op] = [hex(start_addr + int(op,16)),"UH9"]
    elif op == "7153":
        fun[op] = [hex(start_addr + int(op,16)),"UH10"]
    elif op == "769B":
        fun[op] = [hex(start_addr + int(op,16)),"UH11"]
    elif op == "6718":
        fun[op] = [hex(start_addr + int(op,16)),"UH12"]
    elif op == "4F23":
        fun[op] = [hex(start_addr + int(op,16)),"UH13"]
    elif op == "634F":
        fun[op] = [hex(start_addr + int(op,16)),"MEM_UPDATE"]
    else:
        fun[op] = [hex(start_addr + int(op,16)),"UNKNOW HANDLER"]

for opcode in fun:
    print(opcode, fun[opcode])


action = ""
formated = []
for code in trace:
    args = code.split("  ")
    args_f = []
    for arg in args:
        if arg == '' or arg == ' ':
            pass
        else:
            args_f.append(arg)
            
    formated.append(args_f)

for i in range(len(formated)):
    args_f = str(formated[i])
    if "RDI=" in str(args_f):
        rdi = str(args_f).split("RDI=")[1][8:16]
        if rdi[0:4] == "0000" and rdi != "00000001" and rdi != "00000003" and rdi != "00000004"  and rdi != "00000005" and rdi != "00000020" and rdi != "00000100" and rdi != "00000000" :
            action += fun[rdi[4:8]][1]
            action += "\n"
            if fun[rdi[4:8]][1] == "START_FUN":
                func_addr = formated[i+10][-1]
                if "RBX" in func_addr:
                    func_addr = formated[i+11][-1]
                func_addr = func_addr[4:20]
                action += f"CALLING FUN 0x{func_addr}"
                action += "\n"


            
            if fun[rdi[4:8]][1] == "EXITVM":
                break
            

out = open("action_vm.txt","w")
out.write(action)
out.close()
print("VM_Trace virtual Handler saved to file action_vm.txt")
