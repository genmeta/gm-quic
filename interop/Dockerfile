FROM docker.io/martenseemann/quic-network-simulator-endpoint:latest

RUN env

# download and build your QUIC implementation
COPY . /gm-quic

# setup rust
RUN apt-get update && apt-get install -y curl gcc \ 
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y  \ 
    && . "$HOME/.cargo/env" \
    # build the QUIC implementation
    && cd gm-quic \
    && cargo build --release --example http-server \
    && cargo build --release --example http-client \
    && cargo build --release --example h3-client \
    && cargo build --release --example h3-server \
    # copy the binary 
    && mv target/release/examples/http-server / \
    && mv target/release/examples/http-client / \
    && mv target/release/examples/h3-client / \
    && mv target/release/examples/h3-server / \
    # cleanup
    && cd / && rm -rf /gm-quic \
    && rm -rf $HOME/.cargo/registry \
    && rm -rf $HOME/.cargo/git \
    && rustup self uninstall -y \
    && apt-get remove -y curl gcc \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# copy run script and run it
COPY interop/run_endpoint.sh .
RUN chmod +x run_endpoint.sh
ENTRYPOINT [ "./run_endpoint.sh" ]
