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

在client端输入密钥位数（如128）；

按顺序在DN1端输入“1”，随后sgx端输入“1”，随后DN1处输入“2”，之后循环这三个操作直至DN1端提示输入“发送DN1的Label给sgx”；

按顺序在DN2端输入“1”，随后sgx端输入“1”，随后DN2处输入“2”，之后循环这三个操作直至DN2端提示输入“发送DN2的Label给sgx”；

按顺序在DN3端输入“1”，随后sgx端输入“1”，随后DN3处输入“2”，之后循环这三个操作直至DN3端提示输入“发送DN3的Label给sgx”；

按顺序在DN1端输入提示的Label标号，随后DN2端输入提示的Label标号，随后DN3端输入提示的Label标号，随后sgx端输入提示的Label标号，之后重复循环输入所有的Label标号（1-10），最后sgx端得到最终排序的密文（为验证正确性同时输出了明文和密文）。