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
    # php
    php7.4 php7.4-cli php7.4-common php7.4-xml php7.4-mbstring php7.4-xdebug \
    && apt-get -y clean && apt-get -y autoclean && apt-get -y autoremove

RUN echo "xdebug.start_with_request=yes" >> /etc/php/7.4/cli/conf.d/20-xdebug.ini
RUN echo "xdebug.idekey=docker" >> /etc/php/7.4/cli/conf.d/20-xdebug.ini
RUN echo "xdebug.profiler_enable_trigger = 1" >> /etc/php/7.4/cli/conf.d/20-xdebug.ini
RUN echo "xdebug.profiler_enable = 0" >> /etc/php/7.4/cli/conf.d/20-xdebug.ini
RUN echo "xdebug.remote_enable = 1" >> /etc/php/7.4/cli/conf.d/20-xdebug.ini
RUN echo "xdebug.profiler_output_dir = '/tmp'" >> /etc/php/7.4/cli/conf.d/20-xdebug.ini
RUN echo "xdebug.client_port=9003" >> /etc/php/7.4/cli/conf.d/20-xdebug.ini
RUN echo "xdebug.log=/dev/stdout" >> /etc/php/7.4/cli/conf.d/20-xdebug.ini
RUN echo "xdebug.discover_client_host=true" >> /etc/php/7.4/cli/conf.d/20-xdebug.ini
ENV DBGP_IDEKEY="docker"

USER vscode
# setup search path
ENV PATH="/home/vscode/.local/bin/:/home/vscode/.config/composer/vendor/bin/:${PATH}"
RUN mkdir -p ~/.local/bin

# install composer (packet management for php)
RUN cd /tmp && php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');" \
    && php composer-setup.php \
    && php -r "unlink('composer-setup.php');" \
    && mv composer.phar ~/.local/bin/composer

RUN ~/.local/bin/composer global require "squizlabs/php_codesniffer=*"
RUN ~/.local/bin/composer global require "wp-coding-standards/wpcs=*"
