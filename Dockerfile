FROM alpine:3.21

ARG NGINX_VERSION=1.27.3

RUN apk add --no-cache \
    gcc \
    libc-dev \
    make \
    openssl \
    openssl-dev \
    pcre-dev \
    zlib-dev \
    wget \
    perl-dev \
    linux-headers \
    patch

# 1. Download OpenSSL (Standard) - REMOVED, using system openssl-dev
# RUN wget https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz && \
#    tar -zxf openssl-${OPENSSL_VERSION}.tar.gz

# 2. Download Nginx (Standard)
WORKDIR /tmp
RUN echo "Downloading Nginx..." && \
    wget https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && \
    tar -zxf nginx-${NGINX_VERSION}.tar.gz

# 3. Copy our No-Patch Module
COPY . /tmp/ja4_nopatch

# 4. Build Nginx with our module
WORKDIR /tmp/nginx-${NGINX_VERSION}

# Note: We point --add-module to our copied directory
# We use system OpenSSL (from openssl-dev)
    RUN ./configure \
    --with-compat \
    --add-dynamic-module=/tmp/ja4_nopatch \
    --with-http_ssl_module \
    --with-http_v2_module \
    --prefix=/etc/nginx \
    --modules-path=/etc/nginx/modules \
    --with-cc-opt="-Wno-error -O0" \
    && make \
    && make install

# Generate self-signed certificate
RUN openssl req -x509 -newkey rsa:4096 -keyout /etc/nginx/key.pem -out /etc/nginx/cert.pem -days 365 -nodes -subj '/CN=localhost'

# Cleanup
WORKDIR /
RUN rm -rf /tmp/*


# Logs
RUN ln -sf /dev/stdout /etc/nginx/logs/access.log && \
    ln -sf /dev/stderr /etc/nginx/logs/error.log

# Verify module loading
RUN /etc/nginx/sbin/nginx -V

CMD ["/etc/nginx/sbin/nginx", "-g", "daemon off;"]
