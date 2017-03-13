CFLAGS = -std=c11 -D_XOPEN_SOURCE=700 -O3 -Wall
CPPFLAGS = -std=c++14 -O3 -Wall -I/usr/include/modbus
LDFLAGS = -lm -lpthread -lcrypto -lmodbus

OBJ = bemos_modbus.o
BIN = bemos_modbus

.PHONY: clean

$(BIN): $(OBJ)
	$(CXX) $(CPPFLAGS) -o $@ $(OBJ) $(LDFLAGS)

bemos_modbus.o: bemos_modbus.cpp version.hpp
	$(CXX) $(CPPFLAGS) -c $<

clean:
	rm -f $(BIN) $(OBJ)
