from pwn import *
context(log_level="debug")

p = remote('127.0.0.1',12012)

p.recvuntil('P server\n')
p.sendline('USER wdctf2015')
p.recvuntil('wdctf2015\n')
p.sendline('PASS '+'\x03\x05\x07\x19\x21\x0f\x02')
p.interactive()