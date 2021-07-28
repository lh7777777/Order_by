# SGX下多路归并排序项目说明

## 1.系统运行

系统：Ubuntu 18.04，SGX 2.13

语言：C++

使用库：OpenSSL

编译：
client、DN1、DN2、DN3：/Orderby/orderbysgx/*下进行`g++ filename.cpp -lssl -lcrypto -o filename`；
sgx：/Orderby/orderbysgx下进行make。

本代码运行方式：进入/Orderby/orderbysgx，编译完五个项目后，打开五个终端中分别运行./client（代表客户端）、./DN1（代表服务器1）、./DN2（代表服务器2）、./DN3（代表服务器3）、./sgx（代表sgx）。

## 2.主要功能

利用sgx实现对密文的多路归并排序。

## 3.项目使用

运行五个模拟端后：

在client端随机生成AES密钥并发送给sgx，随后输入数据个数N，随机生成N个明文（在input.txt中）进行加密，并将密文哈希后分别发送给三个DN；

按顺序在DN1端输入“1”，随后sgx端输入“1”，随后DN1处输入“2”，之后循环这三个操作直至DN1端提示“DN1密文已全部发送完毕,Sort_DN1已全部接收完毕！”；

按顺序在DN2端输入“1”，随后sgx端输入“1”，随后DN2处输入“2”，之后循环这三个操作直至DN2端提示“DN2密文已全部发送完毕,Sort_DN2已全部接收完毕！”；

按顺序在DN3端输入“1”，随后sgx端输入“1”，随后DN3处输入“2”，之后循环这三个操作直至DN3端提示“DN3密文已全部发送完毕,Sort_DN3已全部接收完毕！”；

按顺序在DN1端输入提示的Label标号，随后DN2端输入提示的Label标号，随后DN3端输入提示的Label标号，随后sgx端输入提示的Label标号，之后在DN1、DN2、DN3和sgx端重复循环输入所有的Label标号，最后sgx端得到最终排序后的密文（为验证正确性同时输出了明文和密文在ouput.txt中）。