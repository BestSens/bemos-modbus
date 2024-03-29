## 2.2.0 (26.02.2024)
- add support for `scale`, `offset` and `coerce_zero` configuration options
- update nlohmann/json library to v3.11.3 (https://github.com/nlohmann/json/releases/tag/v3.11.3)
- update fmt library to v10.2.1 (https://github.com/fmtlib/fmt/releases/tag/10.2.1)
- update spdlog library to v1.13.0 (https://github.com/gabime/spdlog/releases/tag/v1.13.0)
- update cxxopts library to v3.2.0 (https://github.com/jarro2783/cxxopts/releases/tag/v3.2.0)
- add merged attributes

## 2.1.1 (11.01.2023)
- automatically determine target gid & uid
- update nlohmann/json library to v3.11.2 (https://github.com/nlohmann/json/releases/tag/v3.11.2)
- update fmt library to v9.1.0 (https://github.com/fmtlib/fmt/releases/tag/9.1.0)
- update spdlog library to v1.11.0 (https://github.com/gabime/spdlog/releases/tag/v1.11.0)
- update cxxopts library to v3.0.0 (https://github.com/jarro2783/cxxopts/releases/tag/v3.0.0)
- update bone_helper submodule to use boost::asio
- add IPv6 support
- allow to use statically compiled OpenSSL 3
- allow to use with musl
- require C++20

## 2.1.0 (01.12.2020)
- add gitrev and branch to `--version` info
- fix for crash connection handling
- update bone_helper submodule
- update cxxopts library to v2.2.1 (https://github.com/jarro2783/cxxopts/releases/tag/v2.2.1)
- update nlohmann/json library to v3.9.1 (https://github.com/nlohmann/json/releases/tag/v3.9.1)
- add IPv6 support
- don't automatically reload configuration, only with SIGHUP or on restart
- optimize memory footprint and execution speed
- use spdlog v1.8.1 as logging library (https://github.com/gabime/spdlog/releases/tag/v1.8.1)

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
