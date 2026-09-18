FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache \
    curl \
    wget \
    ca-certificates \
    tar \
    gzip \
    iproute2 \
    iptables \
    bash \
    gcompat \
    libc6-compat

# Setup required dirs
RUN mkdir -p /dev/net /etc

# Copy bundled binary as fallback
COPY build/livekadeh_tunnel /usr/local/bin/livekadeh_tunnel
RUN chmod +x /usr/local/bin/livekadeh_tunnel && \
    ln -s /usr/local/bin/livekadeh_tunnel /usr/local/bin/livekadeh

# Copy entrypoint script
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8443/tcp 8443/udp 9090/tcp

ENTRYPOINT ["/entrypoint.sh"]
