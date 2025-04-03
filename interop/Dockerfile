FROM docker.io/martenseemann/quic-network-simulator-endpoint:latest


# download and build your QUIC implementation
COPY . /gm-quic

# setup rust
RUN apt-get update && apt-get install -y curl gcc; \ 
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y ; \ 
    . "$HOME/.cargo/env"; \
    # build the QUIC implementation
    cd gm-quic; \
    cargo build --release --package interop; \
    # copy the binary 
    mv target/release/client /; \
    mv target/release/server /; \
    # cleanup
    cd / && rm -rf /gm-quic

# copy run script and run it
COPY interop/run_endpoint.sh .
RUN chmod +x run_endpoint.sh
ENTRYPOINT [ "./run_endpoint.sh" ]