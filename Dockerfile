FROM debian:8
RUN apt-get update && apt-get install -y libssl-dev libmodbus

COPY bemos_modbus /usr/bin/bemos_modbus
RUN chmod 755 /usr/bin/bemos_modbus

ENTRYPOINT ["/usr/bin/bemos_modbus"]