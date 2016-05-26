from pwn import *
p = process('./guess')
gdb.attach(p,'b*0x0400C3D\nc')
p.interactive()