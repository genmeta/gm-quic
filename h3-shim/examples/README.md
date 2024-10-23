# h3-shim测试

本测试所使用的密钥来自https://github.com/hyperium/h3/tree/master/examples，源代码亦是在其基础上修改而来

你也可以自己签名密钥，并通过server/client的参数指定自己的密钥

## 运行

server.rs和client.rs分别是server和client的源代码，cd到h3-shim文件夹后直接运行即可

所需参数均已预设，你也可以通过`--help`查看帮助，自己指定参数

```shell
# 启动Server
RUST_LOG=info cargo run --example=server
# 启动Client
RUST_LOG=info cargo run --example=client
```

client默认会获取server根目录下的`Cargo.toml`文件并打印出来，你可以通过参数指定获取其他文件

```shell
RUST_LOG=info cargo run --example=client -- https://localhost:4433/examples/server.rs
```

你也可以指定服务的根目录
```shell
RUST_LOG=info cargo run --example=server -- --dir=./examples
```

client默认使用ipv6，如果你运行server时发现使用的是ipv4，请指定client也使用ipv4，否则无法连接

```shell
RUST_LOG=info cargo run --example=client -- -b=127.0.0.1:0
```

如果你想使用Wireshark抓包，你需要设置环境变量`SSLKEYLOGFILE`，然后在启动client时加上`--keylog`参数，以获得keylog文件

```shell
export SSLKEYLOGFILE= <指定一个地方>
RUST_LOG=info cargo run --example=client -- --keylog
```

然后，打开wireshark，Preferences -> Protocols-> TLS ->
(Pre)-Master-Secret log filename 的地方填入上述keylog文件的路径，即可享受wireshark抓包并解密的便利。