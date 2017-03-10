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
#include <cstring>
#include <modbus.h>
#include <sys/socket.h>

int main(int argc, char **argv){
    modbus_mapping_t *mb_mapping;
    uint8_t *query;
    modbus_t *ctx;
    int s = -1;
    int i = 0;
    int rc;

    ctx = modbus_new_tcp("127.0.0.1", 1502);
    query = (uint8_t*)malloc(MODBUS_TCP_MAX_ADU_LENGTH);
    int header_length = modbus_get_header_length(ctx);

    mb_mapping = modbus_mapping_new(10, 10, 10, 10);

    if (mb_mapping == NULL) {
        fprintf(stderr, "Failed to allocate the mapping: %s\n",
                modbus_strerror(errno));
        modbus_free(ctx);
        return -1;
    }

    s = modbus_tcp_listen(ctx, 1);
    modbus_tcp_accept(ctx, &s);

    std::cout << "client connected" << std::endl;

    while(1) {
        do {
            rc = modbus_receive(ctx, query);
            /* Filtered queries return 0 */
        } while (rc == 0);

        if (rc == -1 && errno != EMBBADCRC) {
            /* Quit */
            break;
        }

        mb_mapping->tab_input_registers[1] = i++;
        mb_mapping->tab_input_registers[2] = 2;
        mb_mapping->tab_input_registers[3] = 3;
        mb_mapping->tab_input_registers[4] = 4;
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

    return 0;
}
