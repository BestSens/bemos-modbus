FROM debian:11
RUN apt-get update && apt-get install -y libssl-dev libmodbus-dev

COPY build/bemos_modbus /usr/bin/bemos_modbus
RUN chmod 755 /usr/bin/bemos_modbus

ENTRYPOINT ["/usr/bin/bemos_modbus"]
