FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV container=docker

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        dbus \
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
COPY target/debug/erebor-linux-session-controller \
    /usr/libexec/erebor/erebor-linux-session-controller
COPY target/debug/erebor-linux-process-guard /usr/libexec/erebor/erebor-linux-process-guard
COPY target/debug/erebor-path-broker /usr/libexec/erebor/erebor-path-broker
COPY target/debug/codex-v1-fixture /usr/lib/erebor/codex-v1-fixture
COPY .github/scripts/daemon-systemd-control-plane.sh \
    /usr/local/lib/erebor/daemon-systemd-control-plane.sh
COPY .github/scripts/daemon-installed-session-runtime.sh \
    /usr/local/lib/erebor/daemon-installed-session-runtime.sh
COPY .github/scripts/daemon-phase4-codex-runtime.sh \
    /usr/local/lib/erebor/daemon-phase4-codex-runtime.sh

RUN chmod 0755 \
        /usr/lib/erebor/erebord \
        /usr/libexec/erebor/erebor-linux-session-controller \
        /usr/libexec/erebor/erebor-linux-process-guard \
        /usr/libexec/erebor/erebor-path-broker \
        /usr/lib/erebor/codex-v1-fixture \
        /usr/local/bin/erebor \
        /usr/local/lib/erebor/daemon-systemd-control-plane.sh \
        /usr/local/lib/erebor/daemon-installed-session-runtime.sh \
        /usr/local/lib/erebor/daemon-phase4-codex-runtime.sh

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
