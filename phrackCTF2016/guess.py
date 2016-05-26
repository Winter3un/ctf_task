from pwn import *
p = remote('127.0.0.1',9999)
end = '\xf2'
buf  = ''
payload = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
i  = 50
while i>0:
	buf+='0'+chr(ord(end)-i)
	i-=1

i =0
c_flag=''
while i < 50:
	### create flag
	l = list(buf)
	for x in payload:
		for y in payload:
			p.recvuntil('guess> ')
			if i >=50:
				exit(0)
			l[2*i]=x
			l[2*i+1]=y
			flag = ''.join(l)
			c = chr(int((x+y),16))
	### end
			p.sendline(flag)
			data = p.recvline()
			if data !='Nope.\n':
				
				c_flag += c
				print c_flag
				i+=1
p.interactive()