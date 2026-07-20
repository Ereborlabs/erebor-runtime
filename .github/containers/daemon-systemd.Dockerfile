FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV container=docker

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        dbus \
        libostree-1-1 \
        passwd \
        python3-minimal \
        systemd \
        systemd-sysv \
        util-linux \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY packaging/systemd/erebord.service /etc/systemd/system/erebord.service
COPY target/debug/erebord /usr/lib/erebor/erebord
COPY target/debug/erebor /usr/local/bin/erebor
COPY .github/scripts/daemon-control-plane.sh \
    /usr/local/lib/erebor/daemon-control-plane.sh
COPY .github/scripts/daemon-systemd-control-plane.sh \
    /usr/local/lib/erebor/daemon-systemd-control-plane.sh

RUN chmod 0755 \
        /usr/lib/erebor/erebord \
        /usr/local/bin/erebor \
        /usr/local/lib/erebor/daemon-control-plane.sh \
        /usr/local/lib/erebor/daemon-systemd-control-plane.sh

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
