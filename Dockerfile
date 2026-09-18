FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y gcc make libssl-dev libyaml-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /lanecove
COPY src/common.c src/common.h src/peer.c ./
RUN gcc -pthread -o lanecove peer.c common.c -lssl -lcrypto -lyaml

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    iproute2 libssl3 libyaml-0-2 curl iputils-ping procps nginx net-tools openssh-client traceroute \
    gnupg2 gettext-base \
    && curl -sL https://apt.envoyproxy.io/signing.key | gpg --dearmor -o /usr/share/keyrings/envoy-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/envoy-keyring.gpg] https://apt.envoyproxy.io bookworm main" \
       > /etc/apt/sources.list.d/envoy.list \
    && apt-get update && apt-get install -y envoy \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /lanecove
COPY config/nginx-keepalive.conf /etc/nginx/conf.d/keepalive.conf
COPY scripts/docker-entrypoint.sh scripts/lanecove-create-tunnel.sh config/envoy.yaml.tmpl config/index.html.tmpl ./
COPY --from=builder /lanecove/lanecove ./
COPY config/ ./config/

ENTRYPOINT ["./docker-entrypoint.sh"]
