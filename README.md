# gmtls
TLS base on GMSSL
GmSSL supports the standard TLS 1.2 protocol with SM2/SM3/SM4
使用 gmssl 的双证书

```
何为单证书和双证书？
通常情况下，服务器会部署一张证书，用于签名和加密，这就是所谓的单证书:

签名时，服务器使用自己的私钥加密信息的摘要（签名），客户端使用服务器的公钥（包含在证书中）进行解密，对比该摘要是否正确，若正确，则客户端就确定了服务器的身份，即验签成功。
加密时，服务器和客户端协商出会话密钥（一般为对称密钥），会话密钥的产生根据密钥协商算法的不同，过程有所不同，但都会用到证书的公钥和私钥，也就是说证书也用在加密场景中。
在单证书配置下，服务器端的公钥和私钥由服务器负责保存。私钥需要特别保存，如果泄漏出去就会有很大的安全风险。客户端的公钥和私钥一般在通信过程中动态产生，客户端也不会存储。如果客户端也要配置证书，这种情形不常见，不在讨论之列。

而双证书则包括签名证书和加密证书：

签名证书在签名时使用，仅仅用来验证身份使用，其公钥和私钥均由服务器自己产生，并且由自己保管，CA不负责其保管任务。
加密证书在密钥协商时使用，其私钥和公钥由CA产生，并由CA保管（存根）。

```

## 使用方法
1. 要先安装 gcc 和 gcc-c++；
2. 安装 gmssl (https://github.com/guanzhi/GmSSL/archive/master.zip)，使用 gmssl version 命令确认安装成功；
3. 制作证书；做证书的方法在目录的 **SM2certgen.sh** 脚本里。
4. 编译运行
   ```
   g++ gmtls_server.c  -L /usr/local/include/ -lssl -lcrypto -o gmtls_server
   g++ gmtls_client.c  -L /usr/local/include/ -lssl -lcrypto -o gmtls_client
   ```
