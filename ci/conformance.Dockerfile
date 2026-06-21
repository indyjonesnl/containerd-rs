# syntax=docker/dockerfile:1
FROM ubuntu:24.04

ARG K8S_VERSION=v1.35.6
ARG CRUN_VERSION=1.28
ARG CRICTL_VERSION=v1.35.0
ARG CNI_PLUGINS_VERSION=v1.5.1

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      ca-certificates curl iproute2 iptables ethtool socat conntrack kmod \
      procps iputils-ping mount util-linux golang-go git \
    && rm -rf /var/lib/apt/lists/*

# Tooling install — same script CI uses. Version args bust the cache on bump.
COPY ci/install-tooling.sh /tmp/install-tooling.sh
RUN K8S_VERSION="$K8S_VERSION" CRUN_VERSION="$CRUN_VERSION" \
    CRICTL_VERSION="$CRICTL_VERSION" CNI_PLUGINS_VERSION="$CNI_PLUGINS_VERSION" \
    bash /tmp/install-tooling.sh

WORKDIR /work
