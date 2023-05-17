

FROM rust as builder
WORKDIR /root
COPY . /root
RUN cargo build --release

FROM ubuntu
EXPOSE 53/udp
WORKDIR /root
COPY --from=builder ./root/target/release/updns .
ENV LOG=info,warn,error
ENTRYPOINT ["./updns"]


