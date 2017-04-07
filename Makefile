CFLAGS = -std=c11 -D_XOPEN_SOURCE=700 -O3 -Wall
CPPFLAGS = -std=c++14 -O3 -Wall -I/usr/include/modbus
LDFLAGS = -lm -lpthread -lcrypto -lmodbus

OBJ = bemos_modbus.o
BIN = bemos_modbus

.PHONY: clean

$(BIN): $(OBJ)
	$(CXX) $(CPPFLAGS) -o $@ $(OBJ) $(LDFLAGS)

gitrev.hpp: FORCE
	@echo -n "#define APP_VERSION_GITREV " > $@
	@git rev-parse --verify --short=8 HEAD >> $@

FORCE:

gitrev.hpp.md5: gitrev.hpp
	@md5sum $< | cmp -s $@ -; if test $$? -ne 0; then md5sum $< > $@; fi

bemos_modbus.o: bemos_modbus.cpp version.hpp gitrev.hpp.md5
	$(CXX) $(CPPFLAGS) -c $<

clean:
	rm -f $(BIN) $(OBJ) gitrev.hpp gitrev.hpp.md5
