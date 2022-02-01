FROM mcr.microsoft.com/vscode/devcontainers/base:0-focal

# Install common stuff
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    # common stuff
    bash-completion gcc g++ make build-essential libssl-dev pkg-config \
    software-properties-common

# setup 3rd party repositories
# nodejs
RUN curl -sL https://deb.nodesource.com/setup_lts.x -o /tmp/nodesource_setup.sh \
    && bash /tmp/nodesource_setup.sh \
    # php
    && add-apt-repository ppa:ondrej/php

# install sepcifics for the code
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    # nodejs
    nodejs \
    && apt-get -y clean && apt-get -y autoclean && apt-get -y autoremove


USER vscode
# setup search path
ENV PATH="/home/vscode/.local/bin/:${PATH}"
RUN mkdir -p ~/.local/bin
