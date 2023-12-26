FROM golang:1.21
ARG BIRD_VERSION=v2.0.12

# utils & BIRD deps
RUN apt-get update && \
	apt-get install -y iputils-ping net-tools wget automake bison flex \
	libncurses-dev libreadline-dev

# install BIRD
RUN cd /tmp && \
	git clone https://gitlab.nic.cz/labs/bird.git && cd bird && \
	git checkout tags/$BIRD_VERSION && \
	autoreconf && \
	./configure --prefix=/usr --sysconfdir=/etc --runstatedir=/run/bird && \
	make && make install

EXPOSE 179/tcp