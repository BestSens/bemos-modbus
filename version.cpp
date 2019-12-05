/*
 * version.cpp
 *
 *  Created on: 17.04.2018
 *      Author: Jan Schöppach
 */

#include "version.hpp"
#include <string>
#include "gitrev.hpp"
#include "version_info.hpp"

#define APP_STR_EXP(__A)	#__A
#define APP_STR(__A)		APP_STR_EXP(__A)

#if defined(APP_VERSION_BRANCH) && defined(APP_VERSION_GITREV)
#ifdef DEBUG
#define APP_VERSION			APP_STR(APP_VERSION_MAJOR) "." APP_STR(APP_VERSION_MINOR) "." APP_STR(APP_VERSION_PATCH) "-" APP_STR(APP_VERSION_BRANCH) APP_STR(APP_VERSION_GITREV) "-dbg"
#else
#define APP_VERSION			APP_STR(APP_VERSION_MAJOR) "." APP_STR(APP_VERSION_MINOR) "." APP_STR(APP_VERSION_PATCH) "-" APP_STR(APP_VERSION_BRANCH) APP_STR(APP_VERSION_GITREV)
#endif
#else
#define APP_VERSION			APP_STR(APP_VERSION_MAJOR) "." APP_STR(APP_VERSION_MINOR) "." APP_STR(APP_VERSION_PATCH)
#endif

std::string app_version() {
	return std::string(APP_VERSION);
}

std::string app_compile_date() {
	return std::string(__DATE__) + " " + std::string(__TIME__);
}

bool app_is_dev() {
#ifdef APP_VERSION_BRANCH
	return true;
#else
	return false;
#endif
}