FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

# Install Python and required tools for ona-network-check
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
        python3 \
        python3-pip \
        curl \
        openssl \
        bc \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install optional Python dependencies for enhanced output
RUN pip3 install --no-cache-dir rich
