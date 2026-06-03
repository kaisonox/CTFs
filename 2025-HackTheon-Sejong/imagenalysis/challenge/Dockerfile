FROM ubuntu:22.04 AS base

WORKDIR /root

COPY static /root/static/
COPY templates /root/templates/
COPY imagenalysis /root/imagenalysis
COPY flag /root/flag

COPY start.sh /start.sh
RUN chmod +x /start.sh

CMD [ "/start.sh" ]