#!/bin/bash

# 参考 gm-quic/tests/lib.rs 中的地址
# CASES 定义了10个测试案例，前5个为客户端，后5个为服务器
# NAT类型: 0=FullCone, 1=RestrictedCone, 2=PortRestricted, 3=Dynamic, 4=Symmetric

STUN_SERVER="10.10.0.64:20002"

CLIENT_BIND_ADDRS=(
    "192.168.0.98:6001"  # FullCone
    "192.168.0.96:6002"  # RestrictedCone
    "192.168.0.88:6003"  # PortRestricted
    "192.168.0.86:6004"  # Dynamic
    "192.168.0.84:6005"  # Symmetric
)

CLIENT_OUTER_ADDRS=(
    "10.10.0.98:6001"
    "10.10.0.96:6002"
    "10.10.0.88:6003"
    "10.10.0.86:6004"
    "10.10.0.84:6005"
)

SERVER_BIND_ADDRS=(
    "172.16.0.48:6006"  # FullCone
    "172.16.0.46:6007"  # RestrictedCone
    "172.16.0.38:6008"  # PortRestricted
    "172.16.0.36:6009"  # Dynamic
    "172.16.0.34:6010"  # Symmetric
)

SERVER_OUTER_ADDRS=(
    "10.10.0.48:6006"
    "10.10.0.46:6007"
    "10.10.0.38:6008"
    "10.10.0.36:6009"
    "10.10.0.34:6010"
)

# 默认使用 Port Restricted Client (2) 和 Symmetric Server (4)
CLIENT_INDEX=${1:-2}
SERVER_INDEX=${2:-4}

if [ "$CLIENT_INDEX" -lt 0 ] || [ "$CLIENT_INDEX" -gt 4 ]; then
    echo "客户端索引必须在 0-4 之间"
    exit 1
fi

if [ "$SERVER_INDEX" -lt 0 ] || [ "$SERVER_INDEX" -gt 4 ]; then
    echo "服务器索引必须在 0-4 之间"
    exit 1
fi

BIND1_CLIENT="${CLIENT_BIND_ADDRS[$CLIENT_INDEX]}"
BIND1_SERVER="${SERVER_BIND_ADDRS[$SERVER_INDEX]}"
SERVER_OUTER="${SERVER_OUTER_ADDRS[$SERVER_INDEX]}"
SERVER_AGENT="$STUN_SERVER"

echo "使用客户端索引 $CLIENT_INDEX (地址: $BIND1_CLIENT)"
echo "使用服务器索引 $SERVER_INDEX (地址: $BIND1_SERVER)"
echo "STUN 服务器: $STUN_SERVER"

echo "在 nsa 命名空间中启动服务器进程..."
ip netns exec nsa cargo run -p gm-quic --example traversal_server -- --bind1 "$BIND1_SERVER" --bind2 "$BIND1_SERVER" --stun-server "$STUN_SERVER" > server.log 2>&1 &
SERVER_PID=$!

echo "等待服务器启动和NAT检测..."
sleep 10

if [ "$SERVER_INDEX" -eq 4 ]; then
    # 从日志中提取外网地址
    DETECTED_ADDR=$(grep "new_outer_addr=" server.log | tail -1 | sed 's/.*new_outer_addr=\(.*\)/\1/')
    echo "检测到的外网地址是: $DETECTED_ADDR，是否使用？(y/n)"
    read -p "" confirm
    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
        SERVER_OUTER="$DETECTED_ADDR"
    else
        read -p "请输入服务器的外网地址 (例如 10.10.0.34:22446): " SERVER_OUTER
    fi
fi

echo "使用服务器外网地址: $SERVER_OUTER"

echo "在 nsa 命名空间中启动客户端进程..."
ip netns exec nsa cargo run -p gm-quic --example traversal_client -- --bind1 "$BIND1_CLIENT" --bind2 "$BIND1_CLIENT" --server-outer "$SERVER_OUTER" --server-agent "$SERVER_AGENT" --stun-server "$STUN_SERVER" > client.log 2>&1 &
CLIENT_PID=$!

echo "服务器PID: $SERVER_PID"
echo "客户端PID: $CLIENT_PID"

# 等待客户端结束
wait $CLIENT_PID

# 客户端结束后，终止服务器进程
echo "客户端已结束，终止服务器进程..."
kill $SERVER_PID 2>/dev/null

echo "测试完成。日志文件：server.log 和 client.log"