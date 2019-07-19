CPPFLAGS = -std=c++14 -DNDEBUG -I${SDKTARGETSYSROOT}/usr/include/modbus
LDFLAGS = -lm -lpthread -lcrypto -lmodbus

OBJ = bemos_modbus.o
BIN = bemos_modbus

all: $(BIN)

debug: CPPFLAGS = -std=c++14 -DDEBUG -O0 -Wall -g
debug: $(BIN)

systemd: CPPFLAGS += -DENABLE_SYSTEMD_STATUS
systemd: LDFLAGS += -lsystemd
systemd: $(BIN)

.PHONY: clean

$(BIN): $(OBJ)
	$(CXX) $(CPPFLAGS) -o $@ $(OBJ) $(LDFLAGS)

gitrev.hpp: FORCE
	@echo -n "#define APP_VERSION_GITREV " > $@
	@git rev-parse --verify --short=8 HEAD >> $@

FORCE:

gitrev.hpp.md5: gitrev.hpp
	@md5sum $< | cmp -s $@ -; if test $$? -ne 0; then md5sum $< > $@; fi

bemos_modbus.o: bemos_modbus.cpp version.hpp libs/bone_helper/system_helper.hpp libs/json/single_include/nlohmann/json.hpp libs/cxxopts/include/cxxopts.hpp gitrev.hpp.md5
	$(CXX) $(CPPFLAGS) -c $<

clean:
	rm -f $(BIN) $(OBJ) gitrev.hpp gitrev.hpp.md5
