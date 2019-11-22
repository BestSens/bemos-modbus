ifndef DEBUG
	CPPFLAGS = -std=c++14 -O2 -DNDEBUG -I${SDKTARGETSYSROOT}/usr/include/modbus
else
	CPPFLAGS = -std=c++14 -O0 -DDEBUG -I${SDKTARGETSYSROOT}/usr/include/modbus -Wall -g -rdynamic
endif

LDFLAGS = -lm -lpthread -lcrypto -lmodbus

OBJ = bemos_modbus.o
BIN = bemos_modbus

all: $(BIN)

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
