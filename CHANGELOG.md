## 2.0.1 (unreleased)
- add gitrev and branch to `--version` info

## 2.0.0 (20.04.2020)
- better handling of disconnection on modbus socket
- add crash handler for core dumps
- server can now handle multiple connections
- undefined float values will be mapped as NAN
- populate `active_alarms` with all active alarms and their timestamp

## 1.1.1 (21.11.2019)
- reset registers to 0xFFFF when empty
- get external_data from registers 100 to 120
- update nlohmann/json library to v3.7.3 (https://github.com/nlohmann/json/releases/tag/v3.7.3)
- update cxxopts library to v2.2.0 (https://github.com/jarro2783/cxxopts/releases/tag/v2.2.0)
- update bone_helper submodule
- allow configuration of connection timeout
- add support for libmodbus versions >= 3.1.0
- add commandline options for coil and ext amounts

## 1.1.0 (17.09.2018)
- move data aquisition to parallel thread to decrease response times and jitter
- error state of registers is now indicated a 0x8000 in register and 0 in corresponding coil
- add dynamic mapping of data to input registers via `map_file`
- update nlohmann/json library to v3.2.0 (https://github.com/nlohmann/json/releases/tag/v3.2.0)
- update cxxopts library to v2.1.1 (https://github.com/jarro2783/cxxopts/releases/tag/v2.1.1)

## 1.0.1 (23.07.2018)
- update nlohmann/json library to v3.1.1 (https://github.com/nlohmann/json/releases/tag/v3.1.1)
- remove setting of external_shaft speed

## 1.0.0 (14.09.2017)
