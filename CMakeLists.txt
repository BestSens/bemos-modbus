cmake_minimum_required(VERSION 3.3)

project(bemos-modbus VERSION 2.1.1)

set(MAIN_EXECUTABLE bemos_modbus)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/libs/bone_helper/cmake")

include(pre)

include(fmt)
include(spdlog)
include(bone_helper)
include(cxxopts)
include(json)

add_executable(${MAIN_EXECUTABLE}
	src/bemos_modbus.cpp
	src/version.cpp)

target_include_directories(${MAIN_EXECUTABLE}
	PRIVATE include
	PRIVATE $ENV{SDKTARGETSYSROOT}/usr/include/modbus
)

target_link_libraries(${MAIN_EXECUTABLE} PRIVATE 
	fmt
	spdlog
	bone_helper
	cxxopts
	nlohmann_json::nlohmann_json
	modbus
)

include(post)
