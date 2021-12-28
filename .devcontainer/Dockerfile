FROM ruby:3.0.3-bullseye

RUN useradd -ms /bin/bash vscode \
    && usermod -aG sudo vscode

RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER vscode
RUN gem install solargraph
RUN gem install rufo