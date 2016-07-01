from pwn import *

p = process('./guestbook2')

p.recvuntil('our choice: ')

def add(length,content):
	p.recvuntil('our choice: ')
	p.sendline('2')
	p.recvuntil(' of new post: ')
	p.sendline(str(length))
	p.recvuntil('post: ')
	p.sendline(content)
	p.recvuntil('Done.\n')
def edit(index,length,content):
	p.recvuntil('our choice: ')
	p.sendline('3')
	p.recvuntil('number: ')
	p.sendline(str(index))
	p.recvuntil(' of post: ')
	p.sendline(str(length))
	p.recvuntil('post: ')
	p.sendline(content)
	p.recvuntil('Done.\n')
def dele(index):
	p.recvuntil('our choice: ')
	p.sendline('4')
	p.recvuntil('number: ')
	p.sendline(str(index))
	p.recvuntil('Done.\n')
def list(index):
	p.recvuntil('our choice: ')
	p.sendline('1')

add()