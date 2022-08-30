# warmup1
## 概要  
fileコマンド  
```
./chal: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=24a5eb328ee598833e93f2091ddeb2f9554ca9b5, for GNU/Linux 3.2.0, not stripped
```
checksec  
```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
```
一度だけ入力を行う事ができ、バッファオーバーフローの脆弱性があるのでリターンアドレスの書き換える事ができるがPIEが有効なのでROPを組むことができない。  
## 解法
PIEをどうにかしてバイパスする方法を考える。  
textセクションのアドレスをリークできればROPを組むことができるが、入力は一回だけかつ何かしらの出力を行う関数も実行されないため厳しいと判断した。  
しかし何回か実行してgdbでアタッチしてを繰り返しているうちに、PIEが有効でも下位1byteはPIEによるランダマイズの影響を受けない事がわかった。  
例: 別々で3回実行した際のmain関数のアドレス
```
1st:
0x563497e3e1ce
2nd:
0x557074c981ce
3rd:
0x5630930b61ce
```
何回実行しても下位1byteは固定されている事がわかる。  
また、今回のバイナリはリトルエンディアンであるため、メモリに配置されているリターンアドレスは下位1byteが先頭に存在している。  
つまり範囲は限られるものの、1byteだけリターンアドレスを書き換える事でPIEの影響を受けずに任意のアドレスのコードを実行する事が可能である。  
今回は`win`関数が用意されているため、そこにリターンするように下位1byteを調整した。  
(ちなみにこの手法はPartial overwriteって名前があるそうです)  