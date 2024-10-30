# h3-shim测试

本测试所使用的密钥来自https://github.com/hyperium/h3/tree/master/examples，`h3-server.rs`源代码亦是在其基础上修改而来

你也可以自己签名密钥，并通过server/client的参数指定自己的密钥

`h3-client.rs`使用的是对reqwest`v0.12.8`的fork，其quic实现被替换为为gm-quic

由于`http3`是reqwest的不稳定特性，需要指定`RUSTFLAGS="--cfg=reqwest_unstable"`，否则无法编译examples

``` shell
# 运行之前，设置环境变量
export RUSTFLAGS="--cfg=reqwest_unstable"
export RUST_LOG=info # 非必需，但是建议
```

## 运行

所需命令行参数均已预设，你也可以通过`--help`查看帮助，自己指定参数

cd到`h3-shim`目录下，运行以下命令即可

```shell
# 启动Server
cargo run --example=h3-server
# 启动Client
cargo run --example=h3-client
```

client默认会向`https://localhost:4433/Cargo.toml`发送一个Get请求，你可以通过命令行参数改变请求的url

如下，client会向`https://localhost:4433/examples/server.rs`发送一个Get请求

```shell
cargo run --example=h3-client -- https://localhost:4433/examples/server.rs
```

你也可以指定服务的根目录，或者更改绑定端口
```shell
# 设置服务根目录
cargo run --example=h3-server -- --dir=./examples
# 更改绑定端口
cargo run --example=h3-server -- -b=127.0.0.1:123456
```

## 问题排查

### 找不到文件

如果你遇到类似这样的错误
```
failed to read CA certificate: Os { code: 2, kind: NotFound, message: "No such file or directory" }
failed to read certificate file: Os { code: 2, kind: NotFound, message: "No such file or directory" }
```

说明你并没有移动到`h3-shim`目录下，你可以移动到`h3-shim`目录下，再次运行；或者通过命令行参数指定证书文件，密钥文件的路径

### 无法连接

首先检查你设置的ip和端口是否正确

client和server默认使用ipv6。如果在你的设备上localhost被解析为ipv4，你需要通过`-b`参数指定客户端和服务端使用ipv4地址

```shell
cargo run --example=h3-server -- -b=127.0.0.1:0
cargo run --example=h3-client -- -b=127.0.0.1
```

## 抓包

如果你想使用Wireshark抓包，你需要设置环境变量`SSLKEYLOGFILE`，且在启动client时加上`--keylog`参数，以获得keylog文件

```shell
export SSLKEYLOGFILE= <指定一个地方>
cargo run --example=h3-client -- --keylog
```

然后，打开wireshark，Preferences -> Protocols-> TLS ->
(Pre)-Master-Secret log filename 的地方填入上述keylog文件的路径，即可享受wireshark抓包并解密的便利。