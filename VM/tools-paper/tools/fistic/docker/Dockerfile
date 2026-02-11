# Docker file for Fistic

# debian:11.7
FROM		debian@sha256:9d23db14fbdc095689c423af56b9525538de139a1bbe950b4f0467698fb874d2
MAINTAINER	Thierno Barry "thierno.barry@cea.fr"

RUN	apt-get update \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -y \
        bash \
        binutils \
        bzip2 \
        gcc-arm-none-eabi \
        git \
        gosu \
        libnewlib-arm-none-eabi \
        make \
        pkg-config \
        python3 \
        python3-pip \
        python3-sphinx \
        qemu-system-arm \
        vim \
        wget

# installing fistic
COPY	. sources
RUN	cd sources && \
	pip3 install local/pulseutils .

# the entrypoint script, in order to run the docker container with standard user permissions
#COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
#ENTRYPOINT  ["/usr/local/bin/entrypoint.sh"]

#docker	build --tag fistic:latest docker/
#docker run --name fistic --volume $(pwd):~ -it --env LOCAL_USER_ID=$(id -u) fistic:latest /bin/bash

WORKDIR /homedir/
