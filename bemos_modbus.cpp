/*
 * modbus.cpp
 *
 *  Created on: 10.03.2017
 *      Author: Jan Schöppach
 */

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <cstring>
#include <string>
#include <modbus.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include "version.hpp"
#include "libs/json/src/json.hpp"
#include "libs/bone_helper/netHelper.hpp"

using namespace bestsens;

#define LOGIN_USER "bemos-analysis"
#define LOGIN_HASH "82e324d4dac1dacf019e498d6045835b3998def1c1cece4abf94a3743f149e208f30276b3275fdbb8c60dea4a042c490d73168d41cf70f9cdc3e1e62eb43f8e4"

int main(int argc, char **argv){
    for(int i = 1; i<argc; i++) {
        if(!strcmp(argv[i], "--version")) {
            std::cout << "bemos-modbus version: " << APP_VERSION << std::endl;
            return EXIT_SUCCESS;
        }
    }

    modbus_mapping_t *mb_mapping;
    uint8_t *query;
    modbus_t *ctx;
    int s = -1;
    int i = 0;
    int rc;

    int c;
    int daemon = 0;
    int long_index = 0;

    setlogmask(LOG_UPTO (LOG_INFO));
    openlog("bemos-modbus", LOG_CONS | LOG_NDELAY | LOG_PERROR | LOG_PID, LOG_LOCAL1);

    std::string conn_target = "localhost";
    std::string conn_port = "6450";
    std::string username = std::string(LOGIN_USER);
    std::string password = std::string(LOGIN_HASH);

    opterr = 0;
    static struct option long_options[] = {
        {"connect",				required_argument,	0,	'c'},
        {"daemonize",			no_argument,		0,	'd'},
        {"verbose",				no_argument,		0,	'v'},
        {"port",				required_argument,	0,	'p'},
        {"username",            required_argument,  0,  'u'},
        {"password",            required_argument,  0,  'l'},
        {0, 0, 0, 0}
    };

    while((c = getopt_long(argc, argv, "c:p:dv", long_options, &long_index)) != -1) {
        switch(c) {
            case 'd':
                daemon = 1;
                syslog(LOG_INFO, "start daemonized");
                break;
            case 'v':
                setlogmask(LOG_UPTO (LOG_DEBUG));
                syslog(LOG_INFO, "verbose output enabled");
                break;
            case 'c':
                if(optarg) {
                    conn_target = std::string(optarg);
                    syslog(LOG_INFO, "connecting to %s", conn_target.c_str());
                }
                break;
            case 'p':
                if(optarg) {
                    conn_port = std::string(optarg);
                    syslog(LOG_INFO, "connecting to port %s", conn_port.c_str());
                }
                break;
            case 'u':
                if(optarg) {
                    username = std::string(optarg);
                    syslog(LOG_INFO, "using username %s for login", username.c_str());
                }
                break;
            case 'l':
                if(optarg)
                    password = netHelper::sha512(optarg);

                break;
            case '?':
                syslog(LOG_ERR, "command not found or argument required");
        }
    }

    syslog(LOG_INFO, "starting bemos-modbus %s", APP_VERSION);

    /*
     * open socket
     */
    bestsens::jsonNetHelper * socket = new bestsens::jsonNetHelper(conn_target, conn_port);

    /*
     * connect to socket
     */
    if(socket->connect()) {
        syslog(LOG_CRIT, "connection failed");
        return 1;
    }

    /*
     * login if enabled
     */
    if(!socket->login(username, password)) {
        syslog(LOG_CRIT, "login failed");
        return 1;
    }

    ctx = modbus_new_tcp("127.0.0.1", 1502);
    query = (uint8_t*)malloc(MODBUS_TCP_MAX_ADU_LENGTH);
    int header_length = modbus_get_header_length(ctx);

    mb_mapping = modbus_mapping_new(0, 0, 0, 50);

    if (mb_mapping == NULL) {
        fprintf(stderr, "Failed to allocate the mapping: %s\n",
                modbus_strerror(errno));
        modbus_free(ctx);
        return -1;
    }

    /* Deamonize */
    if(daemon == 1) {
        pid_t pid, sid;

        pid = fork();

        if (pid < 0) { exit(EXIT_FAILURE); }

        //We got a good pid, Close the Parent Process
        if (pid > 0) { exit(EXIT_SUCCESS); }

        //Change File Mask
        umask(0);

        //Create a new Signature Id for our child
        sid = setsid();
        if (sid < 0) { exit(EXIT_FAILURE); }

        //Change Directory
        //If we cant find the directory we exit with failure.
        if ((chdir("/")) < 0) { exit(EXIT_FAILURE); }

        //Close Standard File Descriptors
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

    syslog(LOG_DEBUG, "waiting for connection");

    s = modbus_tcp_listen(ctx, 1);
    modbus_tcp_accept(ctx, &s);

    syslog(LOG_DEBUG, "client connected");

    while(1) {
        do {
            rc = modbus_receive(ctx, query);
            /* Filtered queries return 0 */
        } while (rc == 0);

        if (rc == -1 && errno != EMBBADCRC) {
            /* Quit */
            break;
        }

        /*
         * get channel_data
         */
        json channel_data;

        if(socket->send_command("channel_data", channel_data)) {
            syslog(LOG_DEBUG, "%s", channel_data.dump(2).c_str());

            uint32_t date = 0;
            try {
                date = (uint32_t)channel_data["payload"].value("date", 0);
            } catch(...) {
                date = 0;
            }

            mb_mapping->tab_input_registers[0x00] = (uint16_t)(date >> 16);
            mb_mapping->tab_input_registers[0x01] = (uint16_t)date;

            try {
                mb_mapping->tab_input_registers[0x02] = (uint16_t)channel_data["payload"].value("cage speed", 0);
            } catch(...) {
                mb_mapping->tab_input_registers[0x02] = 0;
            }

            try {
                mb_mapping->tab_input_registers[0x03] = (uint16_t)channel_data["payload"].value("shaft speed", 0);
            } catch(...) {
                mb_mapping->tab_input_registers[0x03] = 0;
            }

            try {
                mb_mapping->tab_input_registers[0x04] = (uint16_t)channel_data["payload"].value("temp mean", 0);
            } catch(...) {
                mb_mapping->tab_input_registers[0x04] = 0;
            }
        }

        rc = modbus_reply(ctx, query, rc, mb_mapping);
        if (rc == -1) {
            break;
        }
    }

    close(s);
    modbus_mapping_free(mb_mapping);
    free(query);
    /* For RTU */
    modbus_close(ctx);
    modbus_free(ctx);

    syslog(LOG_DEBUG, "exited");

    return 0;
}
