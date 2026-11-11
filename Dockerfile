FROM node:20-alpine

RUN apk add --no-cache \
    openssh \
    bash \
    curl \
    git \
    nano \
    htop \
    python3 \
    iproute2 \
    procps \
    coreutils \
    tzdata

ENV TZ=Asia/Jakarta

RUN ssh-keygen -A && \
    mkdir -p /var/run/sshd /root/.ssh /root/workspace && \
    chmod 700 /root/.ssh && \
    sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/root:!/root:*/g' /etc/shadow

RUN printf '\n\033[1;32mWelcome to Arthur WebSSH & SFTP!\033[0m\n\033[0;36m * Portal        : https://arthurg.my.id/ssh\n * Multiplayer   : Mabar SSH 1-Link Ready\n * SFTP Manager  : Integrated\033[0m\n\n' > /etc/motd && \
    printf 'export TERM=xterm-256color\nexport PS1="\\[\\033[01;32m\\]root@arthurg\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]# "\nalias ll="ls -la --color=auto"\nalias ls="ls --color=auto"\n' > /root/.bashrc && \
    cp /root/.bashrc /root/.profile

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY . .
RUN chmod +x /app/entrypoint.sh

EXPOSE 3022

CMD ["/app/entrypoint.sh"]
