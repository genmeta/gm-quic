#!/bin/bash

# Refer to addresses in gm-quic/tests/lib.rs
# CASES define 10 test cases, first 5 are clients, last 5 are servers
# NAT types: 0=FullCone, 1=RestrictedCone, 2=PortRestricted, 3=Dynamic, 4=Symmetric

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

# Default to Port Restricted Client (2) and Symmetric Server (4)
CLIENT_INDEX=${1:-2}
SERVER_INDEX=${2:-4}

if [ "$CLIENT_INDEX" -lt 0 ] || [ "$CLIENT_INDEX" -gt 4 ]; then
    echo "Client index must be between 0-4"
    exit 1
fi

if [ "$SERVER_INDEX" -lt 0 ] || [ "$SERVER_INDEX" -gt 4 ]; then
    echo "Server index must be between 0-4"
    exit 1
fi

BIND1_CLIENT="${CLIENT_BIND_ADDRS[$CLIENT_INDEX]}"
BIND1_SERVER="${SERVER_BIND_ADDRS[$SERVER_INDEX]}"
SERVER_OUTER="${SERVER_OUTER_ADDRS[$SERVER_INDEX]}"
SERVER_AGENT="$STUN_SERVER"

echo "Using client index $CLIENT_INDEX (address: $BIND1_CLIENT)"
echo "Using server index $SERVER_INDEX (address: $BIND1_SERVER)"
echo "STUN server: $STUN_SERVER"

echo "Starting server process in nsa namespace..."
ip netns exec nsa cargo run -p gm-quic --example traversal_server -- --bind1 "$BIND1_SERVER" --bind2 "$BIND1_SERVER" --stun-server "$STUN_SERVER" > server.log 2>&1 &
SERVER_PID=$!

echo "Waiting for server startup and NAT detection..."
sleep 10

if [ "$SERVER_INDEX" -eq 4 ]; then
    # Extract outer address from log
    DETECTED_ADDR=$(grep "new_outer_addr=" server.log | tail -1 | sed 's/.*new_outer_addr=\(.*\)/\1/')
    echo "Detected outer address is: $DETECTED_ADDR, use it? (y/n)"
    read -p "" confirm
    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
        SERVER_OUTER="$DETECTED_ADDR"
    else
        read -p "Please enter the server's outer address (e.g. 10.10.0.34:22446): " SERVER_OUTER
    fi
fi

echo "Using server outer address: $SERVER_OUTER"

echo "Starting client process in nsa namespace..."
ip netns exec nsa cargo run -p gm-quic --example traversal_client -- --bind1 "$BIND1_CLIENT" --bind2 "$BIND1_CLIENT" --server-outer "$SERVER_OUTER" --server-agent "$SERVER_AGENT" --stun-server "$STUN_SERVER" > client.log 2>&1 &
CLIENT_PID=$!

echo "Server PID: $SERVER_PID"
echo "Client PID: $CLIENT_PID"

# Wait for client to finish
wait $CLIENT_PID

# After client finishes, terminate server process
echo "Client has finished, terminating server process..."
kill $SERVER_PID 2>/dev/null

echo "Test completed. Log files: server.log and client.log"