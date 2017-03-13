#ifndef VERSION_HPP_
#define VERSION_HPP_

#define APP_VERSION_MAJOR   1
#define APP_VERSION_MINOR   0
#define APP_VERSION_PATCH   0-dev

#define APP_STR_EXP(__A)    #__A
#define APP_STR(__A)        APP_STR_EXP(__A)

#define APP_VERSION         APP_STR(APP_VERSION_MAJOR) "." APP_STR(APP_VERSION_MINOR) "." APP_STR(APP_VERSION_PATCH)

#endif /* VERSION_HPP_ */
