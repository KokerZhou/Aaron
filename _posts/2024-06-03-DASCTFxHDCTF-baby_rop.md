---
layout:     post
title:      baby_rop详解
subtitle:   DASCTFxHDCTF
date:       2024-6-3
author:     Aaron
header-img: img/post-bg-github-cup.jpg
catalog: true
tags:
    - Rev
    - WriteUp
---

## 分析程序

在程序中动调跟进可以看到一段类似smc的操作
![image-20240604205942743](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20240604205942743.png)

我们在这块代码执行完异或 **0x2a** 后再去查看异或后的值

![image-20240606204004592](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20240606204004592.png)

可以看到一些提示字符和示例用法
![image-20240606204108658](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20240606204108658.png)

再往上是一些数据段我们可以将其全部选中转为汇编代码

![image-20240606204309213](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20240606204309213.png)

我们单步运行跟踪执行流发现可以执行到上方代码，调用了一个rand伪随机然后有两处异或

在第一次执行到

![image-20240606204711569](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20240606204711569.png)

的时候异或的两个寄存器的值分别为 0x25649D88 和 0x25649DA8

![image-20240606204958823](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20240606204958823.png)

得到结果为32，推测是对输入的长度进行校验

对接下来的汇编进行分析

![image-20240606205614657](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20240606205614657.png)

已知 rdi的值为0，r9的值为1，cmovz是两者相等才会将r9的值赋给rdi
如果输入长度不符合32位那么单步步进会走到exit的地址

![](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20240606205524716.png)

再次调整输入的长度发现rdi的值被r9赋值变为1

![image-20240606205851795](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20240606205851795.png)

通过长度验证后发现进入了新的加密函数中，并且将输入存入rdi寄存器中进行加密

![image-20240606210308662](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20240606210308662.png)

转入函数发现

![image-20240606210533612](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20240606210533612.png)

![image-20240606210545625](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20240606210545625.png)

加密函数就是对传入的值进行 加法和异或

## 编写脚本

在执行完第一次长度校验后在第二次循环中退出了程序，应该是在上方的rax与输入的rdi进行校验

我们可以在断点处写idapy代码提取寄存器的值

```python
print('rax = '+hex(get_reg_value('rax')))
print('rsi = '+hex(get_reg_value('rsi')))
```

然后将进行判断的汇编 **cmovz** 修改为 **cmovnz**
然后将输入修改为长度不为32的值
![image-20240606211536988](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20240606211536988.png)

```python
rax = 0x11db2a3f
rsi = 0x9a7ba6984ab8636b
rax = 0x30836d0f
rsi = 0x8f739f7345dc15cf
rax = 0xad48145
rsi = 0x399f7938c150ea1a
rax = 0x1ecb02bb
rsi = 0x7d454145674f5dd5
```

得到数据和key值可得脚本如下

```python
data = [0x9a7ba6984ab8636b, 0x8f739f7345dc15cf, 0x399f7938c150ea1a, 0x7d454145674f5dd5]
enc = [0x11db2a3f, 0x30836d0f, 0xad48145, 0x1ecb02bb]
key = 0x343230324E494448 # HDIN2024
flag = ''

for i in range(len(data)):
    data[i] ^= enc[i]
    tmp = (data[i] - key) ^ key
    for j in range(8):
        byte = (tmp >> (j * 8)) & 0xFF
        flag += chr(byte)
print(flag)
#DASCTF{R0p_is_so_cr34y_1n_re!!!}
```

