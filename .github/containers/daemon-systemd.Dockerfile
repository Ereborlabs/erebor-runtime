FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV container=docker

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        binutils \
        bubblewrap \
        dbus \
        git \
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
COPY target/debug/erebor-path-broker /usr/libexec/erebor/erebor-path-broker
COPY target/debug/erebor-codex-hook /usr/lib/erebor/erebor-codex-hook
COPY target/debug/codex-v1-fixture /usr/lib/erebor/codex-v1-fixture
COPY target/debug/erebor-codex-real-profile /usr/lib/erebor/erebor-codex-real-profile
COPY target/debug/codex-context-dag-inspector /usr/lib/erebor/codex-context-dag-inspector
COPY target/debug/erebor-terminal-lease-probe /usr/lib/erebor/erebor-terminal-lease-probe
COPY .github/scripts/daemon-systemd-control-plane.sh \
    /usr/local/lib/erebor/daemon-systemd-control-plane.sh
COPY .github/scripts/daemon-installed-session-runtime.sh \
    /usr/local/lib/erebor/daemon-installed-session-runtime.sh
COPY .github/scripts/daemon-codex-runtime.sh \
    /usr/local/lib/erebor/daemon-codex-runtime.sh
COPY .github/scripts/daemon-real-codex-runtime.sh \
    /usr/local/lib/erebor/daemon-real-codex-runtime.sh
COPY .github/scripts/codex-real-tui-mock.py \
    /usr/local/lib/erebor/codex-real-tui-mock.py

RUN chmod 0755 \
        /usr/lib/erebor/erebord \
        /usr/libexec/erebor/erebor-linux-session-controller \
        /usr/libexec/erebor/erebor-path-broker \
        /usr/lib/erebor/erebor-codex-hook \
        /usr/lib/erebor/codex-v1-fixture \
        /usr/lib/erebor/erebor-codex-real-profile \
        /usr/lib/erebor/codex-context-dag-inspector \
        /usr/lib/erebor/erebor-terminal-lease-probe \
        /usr/local/bin/erebor \
        /usr/local/lib/erebor/daemon-systemd-control-plane.sh \
        /usr/local/lib/erebor/daemon-installed-session-runtime.sh \
        /usr/local/lib/erebor/daemon-codex-runtime.sh \
        /usr/local/lib/erebor/daemon-real-codex-runtime.sh \
        /usr/local/lib/erebor/codex-real-tui-mock.py \
    && install -d -o root -g root -m 0755 /etc/codex /usr/lib/erebor/codex-hooks \
    && install -o root -g root -m 0644 /dev/null /etc/codex/requirements.toml \
    && install -o root -g root -m 0755 /dev/null \
        /usr/lib/erebor/codex-hooks/erebor-codex-hook \
    && install -o root -g root -m 0755 /dev/null \
        /usr/lib/erebor/codex-hooks/shell-startup \
    && strip --strip-debug /usr/lib/erebor/codex-v1-fixture

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
