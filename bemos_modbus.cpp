/*
 * modbus.cpp
 *
 *  Created on: 10.03.2017
 *	  Author: Jan Schöppach
 */

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <atomic>
#include <thread>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <cstring>
#include <string>
#include <mutex>
#include <modbus.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include "version.hpp"
#include "libs/cxxopts/include/cxxopts.hpp"
#include "libs/json/single_include/nlohmann/json.hpp"
#include "libs/bone_helper/netHelper.hpp"
#include "libs/bone_helper/loopTimer.hpp"
#include "libs/bone_helper/jsonHelper.hpp"
#include "libs/bone_helper/system_helper.hpp"

using namespace bestsens;

system_helper::LogManager logfile("bemos-modbus");

#define LOGIN_USER "bemos-analysis"
#define LOGIN_HASH "82e324d4dac1dacf019e498d6045835b3998def1c1cece4abf94a3743f149e208f30276b3275fdbb8c60dea4a042c490d73168d41cf70f9cdc3e1e62eb43f8e4"

#define USERID 1200
#define GROUPID 880

#define MB_REGISTER_SIZE 1024

std::atomic<bool> running{true};
std::mutex mb_mapping_access_mtx;
bool map_error_displayed[MB_REGISTER_SIZE] = {false};

namespace {
	double getValueFloat(uint16_t data_0, uint16_t data_1) {
		uint32_t data_32 = data_0 + (data_1 << 16);
		return *reinterpret_cast<float*>(&data_32);
	}
}

void data_aquisition(std::string conn_target, std::string conn_port, std::string username, std::string password, json mb_register_map, modbus_mapping_t *mb_mapping, bool has_map_file = false) {
	bestsens::loopTimer timer(std::chrono::seconds(1), 0);
	while(running) {
		/*
		 * set error flags and default values for mappings
		 */
		{
			std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
			for(int i = 0; i <= mb_mapping->nb_input_registers; i++) {
				mb_mapping->tab_input_registers[i] = 0xFFFF;
				mb_mapping->tab_registers[i] = 0xFFFF;
				mb_mapping->tab_input_bits[i] = 0;
			}	
		}

		/*
		 * wait before reconnecting
		 */
		timer.wait_on_tick();

		/*
		 * open socket
		 */
		bestsens::jsonNetHelper socket = bestsens::jsonNetHelper(conn_target, conn_port);
		socket.set_timeout(1);

		/*
		 * connect to socket
		 */
		if(socket.connect()) {
			logfile.write(LOG_CRIT, "connection failed");
			continue;
		}

		/*
		 * login if enabled
		 */
		if(!socket.login(username, password)) {
			logfile.write(LOG_CRIT, "login failed");
			continue;
		}

		logfile.write(LOG_INFO, "connected to BeMoS");

		try {
			bestsens::loopTimer dataTimer(std::chrono::seconds(1), 0);

			/*
			 * register "external_data" algo
			 */
			json j;
			socket.send_command("register_analysis", j, {{"name", "external_data"}});

			while(running) {
				timer.wait_on_tick();

				auto addValue_u16 = [&mb_mapping](uint16_t address_start, const json& source, const std::string& source_name, const std::string& value) {
					try {
						int oldness = std::time(nullptr) - source[source_name].value("date", 0);
						if(oldness > 10)
							throw std::runtime_error("data too old");

						uint16_t response = source[source_name][value];
						std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
						mb_mapping->tab_input_registers[address_start] = response;
						mb_mapping->tab_registers[address_start] = response;
						mb_mapping->tab_input_bits[address_start] = 1;

						map_error_displayed[address_start] = false;
					} catch(const std::exception& e) {
						int log_level = LOG_DEBUG;
						if(map_error_displayed[address_start] == false) {
							log_level = LOG_ERR;
							map_error_displayed[address_start] = true;
						}
						logfile.write(log_level, "error setting map data for 0x%04X (%s.%s): %s", address_start, source_name.c_str(), value.c_str(), e.what());

						mb_mapping->tab_input_registers[address_start] = 0x8000;
						mb_mapping->tab_registers[address_start] = 0x8000;
						mb_mapping->tab_input_bits[address_start] = 0;
					}
				};

				auto addValue_i16 = [&mb_mapping](uint16_t address_start, const json& source, const std::string& source_name, const std::string& value) {
					try {
						int oldness = std::time(nullptr) - source[source_name].value("date", 0);
						if(oldness > 10)
							throw std::runtime_error("data too old");

						int16_t response = source[source_name][value];
						std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
						mb_mapping->tab_input_registers[address_start] = response;
						mb_mapping->tab_registers[address_start] = response;
						mb_mapping->tab_input_bits[address_start] = 1;

						map_error_displayed[address_start] = false;
					} catch(const std::exception& e) {
						int log_level = LOG_DEBUG;
						if(map_error_displayed[address_start] == false) {
							log_level = LOG_ERR;
							map_error_displayed[address_start] = true;
						}
						logfile.write(log_level, "error setting map data for 0x%04X (%s.%s): %s", address_start, source_name.c_str(), value.c_str(), e.what());

						mb_mapping->tab_input_registers[address_start] = 0x8000;
						mb_mapping->tab_registers[address_start] = 0x8000;
						mb_mapping->tab_input_bits[address_start] = 0;
					}
				};

				auto addValue_u32 = [&mb_mapping](uint16_t address_start, const json& source, const std::string& source_name, const std::string& value) {
					try {
						int oldness = std::time(nullptr) - source[source_name].value("date", 0);
						if(oldness > 10)
							throw std::runtime_error("data too old");

						uint32_t response = source[source_name][value];

						response = htonl(response);

						std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
						mb_mapping->tab_input_registers[address_start] = htons((uint16_t)response);
						mb_mapping->tab_registers[address_start] = htons((uint16_t)response);
						mb_mapping->tab_input_registers[address_start+1] = htons((uint16_t)(response >> 16));
						mb_mapping->tab_registers[address_start+1] = htons((uint16_t)(response >> 16));
						mb_mapping->tab_input_bits[address_start] = 1;

						map_error_displayed[address_start] = false;
					} catch(const std::exception& e) {
						int log_level = LOG_DEBUG;
						if(map_error_displayed[address_start] == false) {
							log_level = LOG_ERR;
							map_error_displayed[address_start] = true;
						}
						logfile.write(log_level, "error setting map data for 0x%04X (%s.%s): %s", address_start, source_name.c_str(), value.c_str(), e.what());

						std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
						mb_mapping->tab_input_registers[address_start] = 0x8000;
						mb_mapping->tab_registers[address_start] = 0x8000;
						mb_mapping->tab_input_registers[address_start+1] = 0x8000;
						mb_mapping->tab_registers[address_start+1] = 0x8000;
						mb_mapping->tab_input_bits[address_start] = 0;
					}
				};

				auto addValue_i32 = [&mb_mapping](uint16_t address_start, const json& source, const std::string& source_name, const std::string& value) {
					try {
						int oldness = std::time(nullptr) - source[source_name].value("date", 0);
						if(oldness > 10)
							throw std::runtime_error("data too old");

						int32_t response = source[source_name][value];

						response = htonl(response);

						std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
						mb_mapping->tab_input_registers[address_start] = htons((int16_t)response);
						mb_mapping->tab_registers[address_start] = htons((int16_t)response);
						mb_mapping->tab_input_registers[address_start+1] = htons((int16_t)(response >> 16));
						mb_mapping->tab_registers[address_start+1] = htons((int16_t)(response >> 16));
						mb_mapping->tab_input_bits[address_start] = 1;

						map_error_displayed[address_start] = false;
					} catch(const std::exception& e) {
						int log_level = LOG_DEBUG;
						if(map_error_displayed[address_start] == false) {
							log_level = LOG_ERR;
							map_error_displayed[address_start] = true;
						}
						logfile.write(log_level, "error setting map data for 0x%04X (%s.%s): %s", address_start, source_name.c_str(), value.c_str(), e.what());

						std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
						mb_mapping->tab_input_registers[address_start] = 0x8000;
						mb_mapping->tab_registers[address_start] = 0x8000;
						mb_mapping->tab_input_registers[address_start+1] = 0x8000;
						mb_mapping->tab_registers[address_start+1] = 0x8000;
						mb_mapping->tab_input_bits[address_start] = 0;
					}
				};

				auto addFloat = [&mb_mapping](uint16_t address_start, const json& source, const std::string& source_name, const std::string& value) {
					try {
						int oldness = std::time(nullptr) - source[source_name].value("date", 0);
						if(oldness > 10)
							throw std::runtime_error("data too old");

						float response = source[source_name][value];

						uint16_t* buff = reinterpret_cast<uint16_t*>(&response);

						std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
						mb_mapping->tab_input_registers[address_start] = buff[1];
						mb_mapping->tab_registers[address_start] = buff[1];
						mb_mapping->tab_input_registers[address_start+1] = buff[0];
						mb_mapping->tab_registers[address_start+1] = buff[0];
						mb_mapping->tab_input_bits[address_start] = 1;

						map_error_displayed[address_start] = false;
					} catch(const std::exception& e) {
						int log_level = LOG_DEBUG;
						if(map_error_displayed[address_start] == false) {
							log_level = LOG_ERR;
							map_error_displayed[address_start] = true;
						}
						logfile.write(log_level, "error setting map data for 0x%04X (%s.%s): %s", address_start, source_name.c_str(), value.c_str(), e.what());

						std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
						mb_mapping->tab_input_registers[address_start] = 0x8000;
						mb_mapping->tab_registers[address_start] = 0x8000;
						mb_mapping->tab_input_registers[address_start+1] = 0x8000;
						mb_mapping->tab_registers[address_start+1] = 0x8000;
						mb_mapping->tab_input_bits[address_start] = 0;
					}
				};

				/*
				 * get register map from server when not loaded from file
				 */
				if(has_map_file == false) {
					json channel_attributes;
					if(socket.send_command("channel_attributes", channel_attributes, {{"name", "mb_register_map"}})) {
						logfile.write(LOG_DEBUG, "mb_register_map: %s", channel_attributes.dump(2).c_str());

						if(is_json_array(channel_attributes, "payload"))
							mb_register_map = channel_attributes["payload"];
					}
				}

				/*
				 * get channel_data
				 */
				json channel_data;

				if(socket.send_command("channel_data", channel_data, {{"all", true}})) {
					logfile.write(LOG_DEBUG, "%s", channel_data.dump(2).c_str());

					if(is_json_object(channel_data, "payload")) {
						const json payload = channel_data["payload"];

						for(auto &element : mb_register_map) {
							try {
								int start_address = element["start address"];
								std::string type = element.value("type", "i16");
								std::string source = element.value("source", "channel_data");
								std::string attribute = element["attribute"];

								if(type == "i32") {
									addValue_i32(start_address, payload, source, attribute);
								} else if(type == "u32") {
									addValue_u32(start_address, payload, source, attribute);
								} else if(type == "i16") {
									addValue_i16(start_address, payload, source, attribute);
								} else if(type == "u16") {
									addValue_u16(start_address, payload, source, attribute);
								} else if(type == "float") {
									addFloat(start_address, payload, source, attribute);
								} else {
									addValue_u16(start_address, payload, source, attribute);
								}
							} catch(const std::exception& e) {
								logfile.write(LOG_WARNING, "error reading element of register map: %s (%s)", element.dump().c_str(), e.what());
								continue;
							}
						}
					} else {
						logfile.write(LOG_ERR, "error retrieving data");
						break;
					}
				}

				/*
				 * get external data
				 */
				json payload = {
					{"name", "external_data"}
				};
				
				{
					std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);

					for(int i = 0; i <= 20; i++) {
						uint16_t data = mb_mapping->tab_registers[100 + i];
						mb_mapping->tab_input_registers[100 + i] = data;

						payload["data"]["ext_" + std::to_string(i)] = data;
					}
				}

				socket.send_command("new_data", j, payload);
			}
		} catch(...) {}
	}
}

int main(int argc, char **argv){
	modbus_mapping_t *mb_mapping;
	uint8_t *query;
	modbus_t *ctx;
	int s = -1;
	int rc;

	assert(running.is_lock_free());

	bool daemon = false;
	bool has_map_file = false;
	int port = 502;

	logfile.setMaxLogLevel(LOG_INFO);

	std::string conn_target = "localhost";
	std::string conn_port = "6450";
	std::string username = std::string(LOGIN_USER);
	std::string password = std::string(LOGIN_HASH);

	std::string map_file = "";

	json mb_register_map = {
			{{"start address", 1}, {"type", "i32"}, {"source", "channel_data"}, {"attribute", "date"}},
			{{"start address", 3}, {"type", "float"}, {"source", "channel_data"}, {"attribute", "cage speed"}},
			{{"start address", 5}, {"type", "float"}, {"source", "channel_data"}, {"attribute", "shaft speed"}},
			{{"start address", 7}, {"type", "float"}, {"source", "channel_data"}, {"attribute", "temp mean"}},
			{{"start address", 9}, {"type", "float"}, {"source", "channel_data"}, {"attribute", "stoerlevel"}},
			{{"start address", 11}, {"type", "float"}, {"source", "channel_data"}, {"attribute", "mean rt"}},
			{{"start address", 13}, {"type", "float"}, {"source", "channel_data"}, {"attribute", "mean amp"}},
			{{"start address", 15}, {"type", "float"}, {"source", "channel_data"}, {"attribute", "rms rt"}},
			{{"start address", 17}, {"type", "float"}, {"source", "channel_data"}, {"attribute", "rms amp"}},
			{{"start address", 19}, {"type", "float"}, {"source", "channel_data"}, {"attribute", "temp0"}},
			{{"start address", 21}, {"type", "float"}, {"source", "channel_data"}, {"attribute", "temp1"}},
			{{"start address", 23}, {"type", "float"}, {"source", "channel_data"}, {"attribute", "druckwinkel"}},
			{{"start address", 25}, {"type", "float"}, {"source", "channel_data"}, {"attribute", "axial force"}},
			{{"start address", 27}, {"type", "float"}, {"source", "ks_data"}, {"attribute", "effective value"}}
	};

	/*
	 * parse commandline options
	 */
	{
		cxxopts::Options options("bemos-modbus", "BeMoS one modbus application");

		options.add_options()
			("version", "print version string")
			("h,help", "print help")
			("d,daemonize", "daemonize server", cxxopts::value<bool>(daemon))
			("v,verbose", "verbose output")
			("c,connect", "connect to given host", cxxopts::value<std::string>(conn_target)->default_value(conn_target))
			("p,port", "connect to given port", cxxopts::value<std::string>(conn_port)->default_value(conn_port))
			("username", "username used to connect", cxxopts::value<std::string>(username)->default_value(std::string(LOGIN_USER)))
			("password", "plain text password used to connect", cxxopts::value<std::string>())
			("map_file", "json encoded text file with Modbus mapping data", cxxopts::value<std::string>(map_file))
			("suppress_syslog", "do not output syslog messages to stdout")
			("o,listen", "modbus tcp listen port", cxxopts::value<int>(port))
		;

		try {
			auto result = options.parse(argc, argv);

			if(result.count("help")) {
				std::cout << options.help() << std::endl;
				return EXIT_SUCCESS;
			}

			if(result.count("version")) {
				std::cout << "bemos-modbus version: " << APP_VERSION << std::endl;
				return EXIT_SUCCESS;
			}

			if(daemon) {
				logfile.setEcho(false);
				logfile.write(LOG_INFO, "start daemonized");
			}

			if(result.count("suppress_syslog")) {
				logfile.setEcho(false);
			}

			if(result.count("verbose")) {
				logfile.setMaxLogLevel(LOG_DEBUG);
				logfile.write(LOG_INFO, "verbose output enabled");
			}

			if(result.count("password")) {
				password = bestsens::netHelper::sha512(result["password"].as<std::string>());
			}

			if(result.count("map_file")) {
				logfile.write(LOG_INFO, "map file set to %s", map_file.c_str());
			}
		} catch(const std::exception& e) {
			logfile.write(LOG_CRIT, "%s", e.what());
			return EXIT_FAILURE;
		}
	}

	logfile.write(LOG_INFO, "starting bemos-modbus %s", APP_VERSION);

	/*
	 * Test IEEE 754
	 */
	if(!std::numeric_limits<float>::is_iec559)
		logfile.write(LOG_WARNING, "application wasn't compiled with IEEE 754 standard, floating point values may be out of standard");

	if(map_file != "") {
		std::ifstream file;
		json file_data;
		file.open(map_file);

		if(file.is_open()) {
			std::string str;
			std::string file_contents;

			while(std::getline(file, str)) {
				file_contents += str;
				file_contents.push_back('\n');
			}

			file.close();

			try {
				file_data = json::parse(file_contents);

				if(file_data.is_array()) {
					mb_register_map = file_data;
					has_map_file = true;
				} else {
					logfile.write(LOG_WARNING, "map_file loaded but invalid scheme");
				}
			} catch(const json::exception& e) {
				logfile.write(LOG_WARNING, "map_file set but error loading map data: %s", e.what());
			}
		} else {
			logfile.write(LOG_ERR, "map_file set but not found; using default map data");
		}
	}

	ctx = modbus_new_tcp("127.0.0.1", port);
	query = (uint8_t*)malloc(MODBUS_TCP_MAX_ADU_LENGTH);
	//int header_length = modbus_get_header_length(ctx);

	mb_mapping = modbus_mapping_new(0, MB_REGISTER_SIZE, MB_REGISTER_SIZE, MB_REGISTER_SIZE);

	if (mb_mapping == NULL) {
		logfile.write(LOG_CRIT, "Failed to allocate the mapping: %s", modbus_strerror(errno));
		modbus_free(ctx);
		return EXIT_FAILURE;
	}

	s = modbus_tcp_listen(ctx, 1);

	if(s == -1) {
		logfile.write(LOG_CRIT, "cannot reserve port %d, exiting", port);
		modbus_mapping_free(mb_mapping);
		free(query);
		/* For RTU */
		modbus_close(ctx);
		modbus_free(ctx);
		return EXIT_FAILURE;
	}

	logfile.write(LOG_INFO, "listening on port %d", port);

	if(getuid() == 0) {
		/* process is running as root, drop privileges */
		logfile.write(LOG_INFO, "running as root, dropping privileges");

		if(setgid(GROUPID) != 0)
			logfile.write(LOG_ERR, "setgid: Unable to drop group privileges: %s", strerror(errno));
		if(setuid(USERID) != 0)
			logfile.write(LOG_ERR, "setuid: Unable to drop user privileges: %s", strerror(errno));
	}

	/* spawn aquire thread */ 
	std::thread aquire_inst(data_aquisition, conn_target, conn_port, username, password, mb_register_map, mb_mapping, has_map_file);

	/* Deamonize */
	if(daemon) {
		bestsens::system_helper::daemonize();
		logfile.write(LOG_INFO, "daemon created");
	} else {
		logfile.write(LOG_DEBUG, "skipped daemonizing");
	}

	bestsens::system_helper::systemd::ready();

	while(1) {
		logfile.write(LOG_DEBUG, "waiting for connection...");
		modbus_tcp_accept(ctx, &s);

		logfile.write(LOG_DEBUG, "client connected");

		while(1) {
			do {
				rc = modbus_receive(ctx, query);
				/* Filtered queries return 0 */
			} while (rc == 0);

			if (rc == -1 && errno != EMBBADCRC) {
				logfile.write(LOG_WARNING, "error on modbus connection");
				/* Quit */
				break;
			}

			std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
			rc = modbus_reply(ctx, query, rc, mb_mapping);
			if (rc == -1) {
				break;
			}
		}

		logfile.write(LOG_DEBUG, "client disconnected");
	}

	running = false;

	/* wait on thread exit */
	aquire_inst.join();

	close(s);
	modbus_mapping_free(mb_mapping);
	free(query);
	/* For RTU */
	modbus_close(ctx);
	modbus_free(ctx);

	logfile.write(LOG_DEBUG, "exited");

	return EXIT_SUCCESS;
}
