FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV container=docker

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        busybox-static \
        dbus \
        docker.io \
        libostree-1-1 \
        passwd \
        python3 \
        systemd \
        systemd-sysv \
        util-linux \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY packaging/systemd/erebord.service /etc/systemd/system/erebord.service
COPY target/debug/erebord /usr/lib/erebor/erebord
COPY target/debug/erebor /usr/local/bin/erebor
COPY target/debug/erebor-session-helper /usr/libexec/erebor/erebor-session-helper
COPY target/debug/erebor-linux-process-guard /usr/libexec/erebor/erebor-linux-process-guard
COPY target/debug/erebor-path-broker /usr/libexec/erebor/erebor-path-broker
COPY target/debug/erebor-daemon-session-driver \
    /usr/local/lib/erebor/erebor-daemon-session-driver
COPY .github/scripts/daemon-control-plane.sh \
    /usr/local/lib/erebor/daemon-control-plane.sh
COPY .github/scripts/daemon-systemd-control-plane.sh \
    /usr/local/lib/erebor/daemon-systemd-control-plane.sh
COPY .github/scripts/daemon-installed-session-runtime.sh \
    /usr/local/lib/erebor/daemon-installed-session-runtime.sh

RUN chmod 0755 \
        /usr/lib/erebor/erebord \
        /usr/libexec/erebor/erebor-session-helper \
        /usr/libexec/erebor/erebor-linux-process-guard \
        /usr/libexec/erebor/erebor-path-broker \
        /usr/local/bin/erebor \
        /usr/local/lib/erebor/erebor-daemon-session-driver \
        /usr/local/lib/erebor/daemon-control-plane.sh \
        /usr/local/lib/erebor/daemon-systemd-control-plane.sh \
        /usr/local/lib/erebor/daemon-installed-session-runtime.sh \
    && install -d -m 0755 /etc/docker /opt/erebor/docker-fixture-root/bin \
    && printf '%s\n' '{"storage-driver":"vfs"}' >/etc/docker/daemon.json \
    && cp /bin/busybox /opt/erebor/docker-fixture-root/bin/busybox \
    && ln -s busybox /opt/erebor/docker-fixture-root/bin/sh \
    && ln -s busybox /opt/erebor/docker-fixture-root/bin/sleep \
    && ln -s busybox /opt/erebor/docker-fixture-root/bin/id \
    && ln -s busybox /opt/erebor/docker-fixture-root/bin/printf \
    && tar --numeric-owner -C /opt/erebor/docker-fixture-root -cf \
        /usr/local/lib/erebor/docker-fixture-root.tar . \
    && rm -rf /opt/erebor/docker-fixture-root

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
