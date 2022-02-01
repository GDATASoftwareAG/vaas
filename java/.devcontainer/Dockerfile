FROM mcr.microsoft.com/vscode/devcontainers/base:0-focal

ARG GRADLE_VERSION=7.2

# Install common stuff
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    # common stuff
    bash-completion gcc g++ make build-essential libssl-dev pkg-config \
    software-properties-common

# install Java related stuff
RUN apt-get -y install --no-install-recommends default-jdk
RUN curl -O -L https://services.gradle.org/distributions/gradle-$GRADLE_VERSION-bin.zip \
    && unzip -d /opt/gradle gradle-$GRADLE_VERSION-bin.zip \
    && rm gradle-$GRADLE_VERSION-bin.zip \
    && ln -s /opt/gradle/gradle-$GRADLE_VERSION /opt/gradle/latest
ENV PATH="/opt/gradle/latest/bin:${PATH}"


USER vscode
# setup search path
ENV PATH="/home/vscode/.local/bin/:${PATH}"
RUN mkdir -p ~/.local/bin
