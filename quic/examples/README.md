# gm-quic测试

quic的测试比较复杂，这里借助`quinn`的server来测试，`quinn`的server有一些不错的特性，支持在QUIC连接上，发送HTTP/1.1的请求，相当于在QUIC连接上承载了HTTP/1.1，这对QUIC连接的多路传输非常有帮助。

但是QUIC天生是加密的，需要密钥、证书，同时wireshark抓包软件也需要密钥、证书才能协助测试。

这里预先生成了自签名的根证书，并用根证书签名了"quic.test.net"域名的证书，可用于`quinn`的server绑定这固定的密钥来测试。

## 启动server

首先`clone`下来`quinn`，并切换到`0.11.2`的tag:

```
git clone https://github.com/quinn-rs/quinn.git
git checkout -b 0.11.2 0.11.2
```

预先生成的证书使用的域名是"quic.test.net"，而测试发生在lo网卡上，因此要先将该域名绑定在localhost上：

```
# 以linux为例，其他系统类似手法
echo "quic.test.net 127.0.0.1" >> /etc/hosts
```

接下来编译并启动`quinn`的server，注意启动的时候，要将预先生成的密钥文件指定进去，该server响应HTTP/1.1请求的静态文件夹也可以指定：

```
RUST_LOG=DEBUG cargo run --example server -- ${path_to}/quinn     \
  --key ${path_to}/keychain/quic.test.net/quic-test-net-ECC.key   \
  --cert ${path_to}/keychain/quic.test.net/quic-test-net-ECC.crt  \
  --listen 0.0.0.0:4433                                           \
  --keylog
```

## 使用client测试

此时，可启动`gm-quic`的client去尝试连接`quinn`的server。但要注意，客户端需要用预生成的根证书来验证服务端的证书，不可自己生成，亦不可使用系统内部预定的根证书，除非将预生成的根证书安装到系统里。

```
cargo run --example client -- --domain=quic.test.net                    \
  --root=${path_to}/gm-quic/quic/examples/keychain/root/rootCA-ECC.crt  \
  --addr=127.0.0.1:4433
```

## wireshark抓包

QUIC抓包解密，需要依赖sslkeylog文件，该文件产生与一个连接tls握手的过程。

幸运的是，`rustls`也是支持[`KeyLogFile`](https://docs.rs/rustls/latest/rustls/struct.KeyLogFile.html)的，只需要配置全局变量：

```
mkdir ~/.ssl     # 指定一个地方
export SSLKEYLOGFILE=~/.ssl/sslkeylog.log
```

然后，打开wireshark，Preferences -> Protocols-> TLS ->
(Pre)-Master-Secret log filename 的地方填入上述sslkeylog.log的路径，即可享受wireshark抓包并解密的便利。