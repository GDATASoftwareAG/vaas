FROM mcr.microsoft.com/vscode/devcontainers/base:0-focal

# Install common stuff
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    # common stuff
    bash-completion gcc g++ make build-essential libssl-dev pkg-config \
    software-properties-common

# install sepcifics for the code
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    # dependencies of examples/kde_dolphin
    libglib2.0-dev libcairo2-dev libpango1.0-dev libatk1.0-dev \
    libgdk-pixbuf2.0-dev libsoup2.4-dev libgtk-3-dev libwebkit2gtk-4.0-dev \
    && apt-get -y clean && apt-get -y autoclean && apt-get -y autoremove

USER vscode
# setup search path
ENV PATH="/home/vscode/.cargo/bin:/home/vscode/.local/bin/:${PATH}"
RUN mkdir -p ~/.local/bin

# install rust tooling for the vscode user
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
