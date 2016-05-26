from pwn import *

p  = process('./ftp_s')
gdb.attach(p,'b*0x40157B\nc')
p.interactive()