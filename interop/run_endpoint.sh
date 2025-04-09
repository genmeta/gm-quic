#!/bin/bash

# Set up the routing needed for the simulation
/setup.sh

# The following variables are available for use:
# - ROLE contains the role of this execution context, client or server
# - SERVER_PARAMS contains user-supplied command line parameters
# - CLIENT_PARAMS contains user-supplied command line parameters


run_client() {
    binary="/http-client"

    case "$TESTCASE" in
        "handshake" | "transfer" )
            # do nothing
            ;;
        "h3" )
            binary="/h3-client"
            ;;
        *)
            echo "Unupported test case: $TESTCASE"
            exit 127
            ;;
    esac

    # Start the client
    echo "Starting client with parameters: $CLIENT_PARAMS"
    $binary --alpns hq-interop --qlog-dir $QLOGDIR \
        --skip-verify --save /downloads $CLIENT_PARAMS $REQUESTS
}

run_server() {
    binary="/http-server"

    case "$TESTCASE" in
        "handshake" | "transfer" )
            # do nothing
            ;;
        "h3" )
            binary="/h3-server"
            ;;
        *)
            echo "Unupported test case: $TESTCASE"
            exit 127
            ;;
    esac
    # Start the server
    echo "Starting server with parameters: $SERVER_PARAMS"
    $binary --alpns hq-interop --qlog-dir $QLOGDIR \
        -c /certs/cert.pem -k /certs/server.key -d /www $SERVER_PARAMS
}

if [ "$ROLE" == "client" ]; then
    # Wait for the simulator to start up.
    /wait-for-it.sh sim:57832 -s -t 30
    run_client
elif [ "$ROLE" == "server" ]; then
    run_server
fi