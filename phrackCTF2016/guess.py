from pwn import *
import time
p = remote('127.0.0.1',9999)
context(log_level="debug")
flag = ''
flag+=p32(0x454B4141)
flag+=p32(0x3362397B)
flag+=p32(0x33653535)
flag+=p32(0x32643439)
flag+=p32(0x65303730)
flag+=p32(0x64306462)
flag+=p32(0x35393166)
flag+=p32(0x32623864)
flag+=p32(0x30353433)
flag+=p32(0x32636339)
flag+=p32(0x32373239)
flag+=p32(0x31346362)
flag+='\x32\x7d'
buf = ''
for x in flag:
	buf+=x.encode('hex')
p.recvuntil('guess> ')
time.clock()
p.sendline(buf)
print time.clock()
p.recvuntil('Nope.\n')
p.interactive()