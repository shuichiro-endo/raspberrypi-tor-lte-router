FROM alpine:latest

RUN echo "@edge http://dl-cdn.alpinelinux.org/alpine/edge/community" >> /etc/apk/repositories && \
    apk --no-cache upgrade && \
    apk --no-cache add tor@edge && \ 
    chmod 700 /var/lib/tor

COPY torrc /etc/tor/

EXPOSE 9040 9150

CMD ["/usr/bin/tor", "-f", "/etc/tor/torrc"]
