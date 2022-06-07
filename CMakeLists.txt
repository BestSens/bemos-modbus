cmake_minimum_required(VERSION 3.3)

project(bemos-modbus VERSION 2.1.1)

set(MAIN_EXECUTABLE bemos_modbus)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/libs/bone_helper/cmake")

include(pre)

include(fmt)
include(spdlog)
include(mbedtls)
include(bone_helper)
include(add_cxxopts)
include(json)

add_executable(${MAIN_EXECUTABLE}
	src/bemos_modbus.cpp
)

add_library(version src/version.cpp)
add_dependencies(version version_header)

target_include_directories(${MAIN_EXECUTABLE} PRIVATE
	include
	$ENV{SDKTARGETSYSROOT}/usr/include/modbus
)

target_include_directories(version PRIVATE include)

target_link_libraries(version PRIVATE fmt common_compile_options)
target_link_libraries(${MAIN_EXECUTABLE} PRIVATE
	common_compile_options
	version
	fmt
	spdlog
	bone_helper
	cxxopts
	nlohmann_json::nlohmann_json
	modbus
)

include(post)
