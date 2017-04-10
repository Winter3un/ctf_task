from pwn import *

def is_able(line):
    packed = p32(int(line[2:10],16))
    for x in packed:
        if ord(x) <= 32 or ord(x) > 126:
            return False
    return True



ropchain = ""
with open("ropchain",'r') as f:
	for line in f.readlines():
		if is_able(line):
			ropchain+=line
with open("alpha_rop","w") as f:
	f.write(ropchain)
