#ifndef VERSION_HPP_
#define VERSION_HPP_

#include <string>

std::string app_version();
std::string app_compile_date();
std::string app_compile_flags();
std::string app_linker_flags();
std::string app_compiler_version();
bool app_is_dev();
bool app_is_debug();

#endif /* VERSION_HPP_ */
