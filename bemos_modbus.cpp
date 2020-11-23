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
#include <signal.h>
#include <execinfo.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/socket.h>

#include "version.hpp"
#include "cxxopts.hpp"
#include "nlohmann/json.hpp"
#include "libs/bone_helper/netHelper.hpp"
#include "libs/bone_helper/loopTimer.hpp"
#include "libs/bone_helper/jsonHelper.hpp"
#include "libs/bone_helper/system_helper.hpp"

using namespace bestsens;

system_helper::LogManager logfile("bemos-modbus");

#define LOGIN_USER "bemos-analysis"
#define LOGIN_HASH "82e324d4dac1dacf019e498d6045835b3998def1c1cece4abf94a3743f149e208f30276b3275fdbb8c60dea4a042c490d73168d41cf70f9cdc3e1e62eb43f8e4"

namespace {
	constexpr auto USERID = 1200;
	constexpr auto GROUPID = 880;

	constexpr auto MB_REGISTER_SIZE = 1024;
	constexpr auto NB_CONNECTION = 10;

	const json default_mb_register_map = {			
		{{"start address", 1}, {"type", "i32"}, {"source", "channel_data"}, {"attribute", "date"}, {"ignore oldness", true}},
		{{"start address", 3}, {"type", "float"}, {"source", "channel_data"}, {"attribute", "cage speed"}},
		{{"start address", 5}, {"type", "float"}, {"source", "channel_data"}, {"attribute", "shaft speed"}},
		{{"start address", 7}, {"type", "float"}, {"source", "channel_data"}, {"attribute", "temp mean"}},
		{{"start address", 9}, {"type", "float"}, {"source", "channel_data"}, {"attribute", "kurtosis coe"}},
		{{"start address", 11}, {"type", "float"}, {"source", "channel_data"}, {"attribute", "mean rt"}},
		{{"start address", 13}, {"type", "float"}, {"source", "channel_data"}, {"attribute", "mean amp"}},
		{{"start address", 15}, {"type", "float"}, {"source", "channel_data"}, {"attribute", "rms rt"}},
		{{"start address", 17}, {"type", "float"}, {"source", "channel_data"}, {"attribute", "rms amp"}},
		{{"start address", 19}, {"type", "float"}, {"source", "channel_data"}, {"attribute", "temp0"}},
		{{"start address", 21}, {"type", "float"}, {"source", "channel_data"}, {"attribute", "temp1"}},
		{{"start address", 23}, {"type", "float"}, {"source", "channel_data"}, {"attribute", "druckwinkel"}},
		{{"start address", 25}, {"type", "float"}, {"source", "channel_data"}, {"attribute", "axial force"}},
		{{"start address", 27}, {"type", "float"}, {"source", "ks_data_0"}, {"attribute", "max abs val velocity"}, {"ignore oldness", true}},
		{{"start address", 29}, {"type", "float"}, {"source", "ks_data_1"}, {"attribute", "max abs val velocity"}, {"ignore oldness", true}},
		{{"start address", 31}, {"type", "float"}, {"source", "ks_data_2"}, {"attribute", "max abs val velocity"}, {"ignore oldness", true}},
		{{"start address", 33}, {"type", "float"}, {"source", "ks_data_3"}, {"attribute", "max abs val velocity"}, {"ignore oldness", true}},
		{{"start address", 35}, {"type", "float"}, {"source", "ks_data_4"}, {"attribute", "max abs val velocity"}, {"ignore oldness", true}},
		{{"start address", 37}, {"type", "float"}, {"source", "ks_data_5"}, {"attribute", "max abs val velocity"}, {"ignore oldness", true}},
		{{"start address", 39}, {"type", "float"}, {"source", "ks_data_6"}, {"attribute", "max abs val velocity"}, {"ignore oldness", true}},
		{{"start address", 41}, {"type", "float"}, {"source", "ks_data_7"}, {"attribute", "max abs val velocity"}, {"ignore oldness", true}},
		{{"start address", 43}, {"type", "i16"}, {"source", "ack"}, {"attribute", "ack"}},
		{{"start address", 44}, {"type", "i32"}, {"source", "ks_data_0"}, {"attribute", "date"}, {"ignore oldness", true}},
		{{"start address", 46}, {"type", "i32"}, {"source", "ks_data_1"}, {"attribute", "date"}, {"ignore oldness", true}},
		{{"start address", 48}, {"type", "i32"}, {"source", "ks_data_2"}, {"attribute", "date"}, {"ignore oldness", true}},
		{{"start address", 50}, {"type", "i32"}, {"source", "ks_data_3"}, {"attribute", "date"}, {"ignore oldness", true}},
		{{"start address", 52}, {"type", "i32"}, {"source", "ks_data_4"}, {"attribute", "date"}, {"ignore oldness", true}},
		{{"start address", 54}, {"type", "i32"}, {"source", "ks_data_5"}, {"attribute", "date"}, {"ignore oldness", true}},
		{{"start address", 56}, {"type", "i32"}, {"source", "ks_data_6"}, {"attribute", "date"}, {"ignore oldness", true}},
		{{"start address", 58}, {"type", "i32"}, {"source", "ks_data_7"}, {"attribute", "date"}, {"ignore oldness", true}}
	};

	std::atomic<bool> running{true};
	std::atomic<bool> reload_config{true};
	std::mutex mb_mapping_access_mtx;

	enum representation_type_t {
		i16, u16, i32, u32, i64, u64, float32
	};

	struct mb_map_config_t {
		uint16_t start_address;
		representation_type_t type;
		std::string source;
		std::string identifier;
		bool ignore_oldness;
		bool map_error_displayed = false;
	};	

	double getValueFloat(uint16_t data_0, uint16_t data_1) {
		uint32_t data_32 = data_0 + (data_1 << 16);
		return *reinterpret_cast<float*>(&data_32);
	}

	int main_socket = -1;

	void handle_signal(int signal) {
		switch(signal) {
			case SIGINT: 
			case SIGTERM: shutdown(main_socket, SHUT_RDWR); running = false; break;
			case SIGHUP: reload_config = true; break;
		}
	}

	std::vector<mb_map_config_t> update_configuration(bestsens::jsonNetHelper& socket, const std::string& map_file) {
		std::vector<mb_map_config_t> mb_map_config = {};
		json mb_register_map;
		bool has_map_file = false;

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

		/*
		 * get register map from server when not loaded from file
		 */
		if(has_map_file == false) {
			json channel_attributes;
			if(socket.send_command("channel_attributes", channel_attributes, {{"name", "mb_register_map"}})) {
				logfile.write(LOG_DEBUG, "mb_register_map: %s", channel_attributes.dump(2).c_str());

				if(is_json_array(channel_attributes, "payload") && channel_attributes["payload"].size() > 0)
					mb_register_map = channel_attributes["payload"];
			}

			if(!mb_register_map.size())
				mb_register_map = default_mb_register_map;
		}

		for(const auto& e : mb_register_map) {
			try {
				mb_map_config_t temp;
				temp.start_address = e["start address"];
				temp.source = e.value("source", "channel_data");;
				temp.identifier = e["attribute"];
				temp.ignore_oldness = e.value("ignore oldness", false);
				temp.map_error_displayed = false;

				std::string type = e.value("type", "i16");

				if(type == "i16")
					temp.type = i16;
				else if(type == "u16")
					temp.type = u16;
				else if(type == "i32")
					temp.type = i32;
				else if(type == "u32")
					temp.type = u32;
				else if(type == "i64")
					temp.type = i64;
				else if(type == "u64")
					temp.type = u64;
				else if(type == "float")
					temp.type = float32;
				else
					temp.type = i16;

				mb_map_config.push_back(temp);
			} catch(const std::exception& e) {
				logfile.write(LOG_ERR, "error adding register map: %s", e.what());
			}
		}

		return mb_map_config;
	}
}

void data_aquisition(std::string conn_target, std::string conn_port, std::string username, std::string password, modbus_mapping_t *mb_mapping, const std::string& map_file, unsigned int coil_amount, unsigned int ext_amount) {
	std::vector<std::string> source_list = {};
	std::vector<std::string> identifier_list = {};
	std::vector<mb_map_config_t> mb_map_config;
	bestsens::loopTimer timer(std::chrono::seconds(5), 1);
	while(running) {
		/*
		 * set error flags and default values for mappings
		 */
		{
			std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
			for(int i = 0; i < mb_mapping->nb_input_registers; i++) {
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
		bestsens::jsonNetHelper socket(conn_target, conn_port);
		socket.set_timeout(1);

		/*
		 * connect to socket
		 */
		if(socket.connect()) {
			throw std::runtime_error("connection failed");
		}

		/*
		 * login if enabled
		 */
		if(!socket.login(username, password)) {
			throw std::runtime_error("login failed");
		}

		logfile.write(LOG_INFO, "connected to BeMoS");

		try {
			bestsens::loopTimer dataTimer(std::chrono::seconds(1), 0);

			/*
			 * register "external_data" algo
			 */
			json j;
			socket.send_command("register_analysis", j, {{"name", "external_data"}});
			socket.send_command("register_analysis", j, {{"name", "active_coils"}});

			while(running) {
				dataTimer.wait_on_tick();

				auto addValue_u16 = [&mb_mapping](const json& source, mb_map_config_t& config) {
					try {
						int oldness = std::time(nullptr) - source[config.source].value("date", 0);
						if(oldness > 10 && !config.ignore_oldness)
							throw std::runtime_error("data too old");

						uint16_t response = source[config.source][config.identifier];
						std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
						mb_mapping->tab_input_registers[config.start_address] = response;
						mb_mapping->tab_registers[config.start_address] = response;
						mb_mapping->tab_input_bits[config.start_address] = 1;

						config.map_error_displayed = false;
					} catch(const std::exception& e) {
						int log_level = LOG_DEBUG;
						if(config.map_error_displayed == false) {
							log_level = LOG_ERR;
							config.map_error_displayed = true;
						}
						logfile.write(log_level, "error setting map data for 0x%04X (%s.%s): %s", config.start_address, config.source.c_str(), config.identifier.c_str(), e.what());

						std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
						mb_mapping->tab_input_registers[config.start_address] = 0x8000;
						mb_mapping->tab_registers[config.start_address] = 0x8000;
						mb_mapping->tab_input_bits[config.start_address] = 0;
					}
				};

				auto addValue_i16 = [&mb_mapping](const json& source, mb_map_config_t& config) {
					try {
						int oldness = std::time(nullptr) - source[config.source].value("date", 0);
						if(oldness > 10 && !config.ignore_oldness)
							throw std::runtime_error("data too old");

						int16_t response = source[config.source][config.identifier];
						std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
						mb_mapping->tab_input_registers[config.start_address] = response;
						mb_mapping->tab_registers[config.start_address] = response;
						mb_mapping->tab_input_bits[config.start_address] = 1;

						config.map_error_displayed = false;
					} catch(const std::exception& e) {
						int log_level = LOG_DEBUG;
						if(config.map_error_displayed == false) {
							log_level = LOG_ERR;
							config.map_error_displayed = true;
						}
						logfile.write(log_level, "error setting map data for 0x%04X (%s.%s): %s", config.start_address, config.source.c_str(), config.identifier.c_str(), e.what());

						std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
						mb_mapping->tab_input_registers[config.start_address] = 0x8000;
						mb_mapping->tab_registers[config.start_address] = 0x8000;
						mb_mapping->tab_input_bits[config.start_address] = 0;
					}
				};

				auto addValue_u32 = [&mb_mapping](const json& source, mb_map_config_t& config) {
					try {
						int oldness = std::time(nullptr) - source[config.source].value("date", 0);
						if(oldness > 10 && !config.ignore_oldness)
							throw std::runtime_error("data too old");

						uint32_t response = source[config.source][config.identifier];

						response = htonl(response);

						std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
						mb_mapping->tab_input_registers[config.start_address] = htons((uint16_t)response);
						mb_mapping->tab_registers[config.start_address] = htons((uint16_t)response);
						mb_mapping->tab_input_registers[config.start_address+1] = htons((uint16_t)(response >> 16));
						mb_mapping->tab_registers[config.start_address+1] = htons((uint16_t)(response >> 16));
						mb_mapping->tab_input_bits[config.start_address] = 1;

						config.map_error_displayed = false;
					} catch(const std::exception& e) {
						int log_level = LOG_DEBUG;
						if(config.map_error_displayed == false) {
							log_level = LOG_ERR;
							config.map_error_displayed = true;
						}
						logfile.write(log_level, "error setting map data for 0x%04X (%s.%s): %s", config.start_address, config.source.c_str(), config.identifier.c_str(), e.what());

						std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
						mb_mapping->tab_input_registers[config.start_address] = 0x8000;
						mb_mapping->tab_registers[config.start_address] = 0x8000;
						mb_mapping->tab_input_registers[config.start_address+1] = 0x8000;
						mb_mapping->tab_registers[config.start_address+1] = 0x8000;
						mb_mapping->tab_input_bits[config.start_address] = 0;
					}
				};

				auto addValue_i32 = [&mb_mapping](const json& source, mb_map_config_t& config) {
					try {
						int oldness = std::time(nullptr) - source[config.source].value("date", 0);
						if(oldness > 10 && !config.ignore_oldness)
							throw std::runtime_error("data too old");

						int32_t response = source[config.source][config.identifier];

						response = htonl(response);

						std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
						mb_mapping->tab_input_registers[config.start_address] = htons((int16_t)response);
						mb_mapping->tab_registers[config.start_address] = htons((int16_t)response);
						mb_mapping->tab_input_registers[config.start_address+1] = htons((int16_t)(response >> 16));
						mb_mapping->tab_registers[config.start_address+1] = htons((int16_t)(response >> 16));
						mb_mapping->tab_input_bits[config.start_address] = 1;

						config.map_error_displayed = false;
					} catch(const std::exception& e) {
						int log_level = LOG_DEBUG;
						if(config.map_error_displayed == false) {
							log_level = LOG_ERR;
							config.map_error_displayed = true;
						}
						logfile.write(log_level, "error setting map data for 0x%04X (%s.%s): %s", config.start_address, config.source.c_str(), config.identifier.c_str(), e.what());

						std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
						mb_mapping->tab_input_registers[config.start_address] = 0x8000;
						mb_mapping->tab_registers[config.start_address] = 0x8000;
						mb_mapping->tab_input_registers[config.start_address+1] = 0x8000;
						mb_mapping->tab_registers[config.start_address+1] = 0x8000;
						mb_mapping->tab_input_bits[config.start_address] = 0;
					}
				};

				auto addFloat = [&mb_mapping](const json& source, mb_map_config_t& config) {
					try {
						int oldness = std::time(nullptr) - source[config.source].value("date", 0);
						if(oldness > 10 && !config.ignore_oldness)
							throw std::runtime_error("data too old");

						float response = source[config.source][config.identifier];

						uint16_t* buff = reinterpret_cast<uint16_t*>(&response);

						std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
						mb_mapping->tab_input_registers[config.start_address] = buff[1];
						mb_mapping->tab_registers[config.start_address] = buff[1];
						mb_mapping->tab_input_registers[config.start_address+1] = buff[0];
						mb_mapping->tab_registers[config.start_address+1] = buff[0];
						mb_mapping->tab_input_bits[config.start_address] = 1;

						config.map_error_displayed = false;
					} catch(const std::exception& e) {
						int log_level = LOG_DEBUG;
						if(config.map_error_displayed == false) {
							log_level = LOG_ERR;
							config.map_error_displayed = true;
						}
						logfile.write(log_level, "error setting map data for 0x%04X (%s.%s): %s", config.start_address, config.source.c_str(), config.identifier.c_str(), e.what());

						std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
						mb_mapping->tab_input_registers[config.start_address] = 0x7FFF;
						mb_mapping->tab_registers[config.start_address] = 0x7FFF;
						mb_mapping->tab_input_registers[config.start_address+1] = 0xFFFF;
						mb_mapping->tab_registers[config.start_address+1] = 0xFFFF;
						mb_mapping->tab_input_bits[config.start_address] = 0;
					}
				};

				if(reload_config) {
					mb_map_config = update_configuration(socket, map_file);

					source_list.clear();
					identifier_list.clear();
					for(const auto& e : mb_map_config) {
						try {
							const std::string source = e.source;
							const std::string identifier = e.identifier;
							auto it = std::find(source_list.begin(), source_list.end(), source);
							auto it2 = std::find(identifier_list.begin(), identifier_list.end(), identifier);

							if(it == source_list.end())
								source_list.push_back(source);

							if(it2 == identifier_list.end())
								identifier_list.push_back(identifier);
						} catch(...) {}
					}

					logfile.write(LOG_INFO, "configuration reloaded");

					reload_config = false;
				}

				/*
				 * get channel_data
				 */
				json channel_data;

				static struct {
					int id = -1;
					int ts;
				} ack;

				if(socket.send_command("channel_data", channel_data, {{"name", source_list}, {"filter", identifier_list}})) {
					logfile.write(LOG_DEBUG, "%s", channel_data.dump(2).c_str());

					if(is_json_object(channel_data, "payload")) {
						const json payload = channel_data["payload"];

						try {
							int new_ts = payload["ack"]["date"];

							if(new_ts != ack.ts) {
								ack.id = payload["ack"]["ack"];
								ack.ts = payload["ack"]["date"];
							} else {
								ack.id = -1;
								json response;
								socket.send_command("new_data", response, {{"name", "ack"}, {"data", {{"ack", -1}}}});
							}
						} catch(...) {
							ack.id = -1;
						}

						for(auto &element : mb_map_config) {
							try {
								if(element.type == i32) {
									addValue_i32(payload, element);
								} else if(element.type == u32) {
									addValue_u32(payload, element);
								} else if(element.type == i16) {
									addValue_i16(payload, element);
								} else if(element.type == u16) {
									addValue_u16(payload, element);
								} else if(element.type == float32) {
									addFloat(payload, element);
								} else {
									addValue_u16(payload, element);
								}
							} catch(const std::exception& e) {
								logfile.write(LOG_WARNING, "error reading element of register map: %s", e.what());
								continue;
							}
						}
					} else {
						logfile.write(LOG_ERR, "error retrieving data");
						break;
					}
				}

				json active_coils = {
					{"name", "active_coils"}
				};

				if(socket.send_command("channel_data", channel_data, {{"name", "active_coils"}}, 2)) {
					logfile.write(LOG_DEBUG, "%s", channel_data.dump(2).c_str());

					if(is_json_object(channel_data, "payload")) {
						const json payload = channel_data["payload"];

						try {
							active_coils["data"] = payload["active_coils"];

							if(active_coils["data"].count("date"))
								active_coils["data"].erase("date");
						} catch(...) {}
					}
				}
				
				try {
					/*
					 * get external data
					 */
					json payload = {
						{"name", "external_data"},
						{"data", {}}
					};

					std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);

					for(unsigned int i = 0; i < (ext_amount + 1) * 2; i++) 
						mb_mapping->tab_input_registers[100 + i] = mb_mapping->tab_registers[100 + i];

					for(unsigned int i = 0; i < ext_amount; i++)
						payload["data"]["ext_" + std::to_string(i + 1)] = getValueFloat(mb_mapping->tab_registers[101 + i * 2], mb_mapping->tab_registers[100 + i * 2]);

					payload["data"]["ext_" + std::to_string(ext_amount + 1)] = mb_mapping->tab_registers[101 + ext_amount * 2];

					for(unsigned int i = 0; i < coil_amount; i++) {
						bool data = mb_mapping->tab_bits[i];

						const std::string coil_name("coil_" + std::to_string(i + 1));

						payload["data"][coil_name] = data;

						if(!data) {
							try {
								active_coils["data"].erase(coil_name);
							} catch(...) {}
						} else {
							if(active_coils["data"].count(coil_name) == 0 || ack.id == i + 1)
								active_coils["data"][coil_name] = std::time(nullptr);
						}
					}

					socket.send_command("new_data", j, payload);
					socket.send_command("new_data", j, active_coils);
				} catch(const std::exception &e) {
					logfile.write(LOG_ERR, "error parsing external data: %s", e.what());
				}
			}
		} catch(const std::exception &e) {
			logfile.write(LOG_ERR, "exception: %s", e.what());
		}
	}
}

std::string getHostname(modbus_t* ctx) {
	char hostname[40];
	
	int sock_fd = modbus_get_socket(ctx);
	struct sockaddr addr;
	socklen_t addr_len = sizeof(addr);
	getpeername(sock_fd, &addr, &addr_len);

	if(addr.sa_family == AF_INET)
		inet_ntop(AF_INET, &(reinterpret_cast<struct sockaddr_in *>(&addr))->sin_addr, hostname, 40);
	else if (addr.sa_family == AF_INET6)
		inet_ntop(AF_INET6, &(reinterpret_cast<struct sockaddr_in6 *>(&addr))->sin6_addr, hostname, 40);
	else {
		throw std::runtime_error("Unknown socket type passed to worker()");
	}

	return std::string(hostname);
}

int main(int argc, char **argv){
	modbus_mapping_t *mb_mapping;
	modbus_t *ctx;

	assert(running.is_lock_free());
	struct sigaction action;
	memset(&action, 0, sizeof(struct sigaction));
	action.sa_handler = handle_signal;
	action.sa_flags = SA_RESTART;
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGHUP, &action, NULL);

	bool daemon = false;
	std::string port = "502";
	int mb_to_usec = 500000;

	unsigned int coil_amount = 144;
	unsigned int ext_amount = 32;

	logfile.setMaxLogLevel(LOG_INFO);

	std::string conn_target = "localhost";
	std::string conn_port = "6450";
	std::string username = std::string(LOGIN_USER);
	std::string password = std::string(LOGIN_HASH);

	std::string map_file = "";

	json mb_register_map = default_mb_register_map;

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
			("o,listen", "modbus tcp listen port", cxxopts::value<std::string>(port))
			("t,timeout", "modbus tcp timeout in us", cxxopts::value<int>(mb_to_usec))
			("coil_amount", "amount of coils injected to external_data", cxxopts::value<unsigned int>(coil_amount))
			("ext_amount", "amount of ext values injected to external_data", cxxopts::value<unsigned int>(ext_amount))
		;

		try {
			auto result = options.parse(argc, argv);

			if(result.count("help")) {
				std::cout << options.help() << std::endl;
				return EXIT_SUCCESS;
			}

			if(result.count("version")) {
				std::cout << "bemos-modbus version: " << app_version() << std::endl;

				if(result.count("verbose")) {
					std::cout << "git branch: " << app_git_branch() << std::endl;
					std::cout << "git revision: " << app_git_revision() << std::endl;
					std::cout << "compiled @ " << app_compile_date() << std::endl;
					std::cout << "compiler version: " << app_compiler_version() << std::endl;
					std::cout << "compiler flags: " << app_compile_flags() << std::endl;
					std::cout << "linker flags: " << app_linker_flags() << std::endl;
				}

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

			if(result.count("timeout")) {
				logfile.write(LOG_INFO, "modbus timeout set to %d us", mb_to_usec);
			}
		} catch(const std::exception& e) {
			logfile.write(LOG_CRIT, "%s", e.what());
			return EXIT_FAILURE;
		}
	}

	if(coil_amount > MB_REGISTER_SIZE)
		coil_amount = MB_REGISTER_SIZE;

	if(ext_amount > (MB_REGISTER_SIZE - 100) / 2)
		ext_amount = (MB_REGISTER_SIZE - 100) / 2;

	logfile.write(LOG_INFO, "starting bemos-modbus %s", app_version().c_str());
	logfile.write(LOG_INFO, "generating %u coils", coil_amount);
	logfile.write(LOG_INFO, "generating %u ext values", ext_amount);

	/*
	 * Test IEEE 754
	 */
	if(!std::numeric_limits<float>::is_iec559)
		logfile.write(LOG_WARNING, "application wasn't compiled with IEEE 754 standard, floating point values may be out of standard");
	
	ctx = modbus_new_tcp_pi("::0", port.c_str());
	
	if(ctx == NULL) {
		logfile.write(LOG_CRIT, "Unable to allocate libmodbus context: %s", modbus_strerror(errno));
		return EXIT_FAILURE;
	}

	#if LIBMODBUS_VERSION_CHECK(3, 1, 0)
		modbus_set_response_timeout(ctx, 0, mb_to_usec);
	#else
		struct timeval response_timeout;
		response_timeout.tv_sec = 0;
		response_timeout.tv_usec = mb_to_usec;
		modbus_set_response_timeout(ctx, &response_timeout);
	#endif

	mb_mapping = modbus_mapping_new(MB_REGISTER_SIZE, MB_REGISTER_SIZE, MB_REGISTER_SIZE, MB_REGISTER_SIZE);

	if(mb_mapping == NULL) {
		logfile.write(LOG_CRIT, "Failed to allocate the mapping: %s", modbus_strerror(errno));
		modbus_free(ctx);
		return EXIT_FAILURE;
	}

	main_socket = modbus_tcp_pi_listen(ctx, NB_CONNECTION);

	if(main_socket == -1) {
		logfile.write(LOG_CRIT, "cannot reserve port %s, exiting", port.c_str());
		modbus_mapping_free(mb_mapping);
		/* For RTU */
		modbus_close(ctx);
		modbus_free(ctx);
		return EXIT_FAILURE;
	}

	logfile.write(LOG_INFO, "listening on port %s", port.c_str());

	if(getuid() == 0) {
		/* process is running as root, drop privileges */
		logfile.write(LOG_INFO, "running as root, dropping privileges");

		if(setgid(GROUPID) != 0)
			logfile.write(LOG_ERR, "setgid: Unable to drop group privileges: %s", strerror(errno));
		if(setuid(USERID) != 0)
			logfile.write(LOG_ERR, "setuid: Unable to drop user privileges: %s", strerror(errno));
	}

	/* spawn aquire thread */ 
	std::thread aquire_inst(data_aquisition, conn_target, conn_port, username, password, mb_mapping, map_file, coil_amount, ext_amount);

	/* Deamonize */
	if(daemon) {
		bestsens::system_helper::daemonize();
		logfile.write(LOG_INFO, "daemon created");
	} else {
		logfile.write(LOG_DEBUG, "skipped daemonizing");
	}

	fd_set refset;

	/* Clear the reference set of socket */
	FD_ZERO(&refset);
	/* Add the server socket */
	FD_SET(main_socket, &refset);

	/* Keep track of the max file descriptor */
	int fdmax = main_socket;
	int active_connections = 0;

	bestsens::system_helper::systemd::ready();
	bestsens::system_helper::systemd::status("waiting for modbus connection");

	logfile.write(LOG_INFO, "waiting for connection...");

	while(running) {
		fd_set rdset = refset;
		if(fdmax >= FD_SETSIZE - 1) {
			logfile.write(LOG_CRIT, "error: maximum fd reached");
			break;
		}

		if(pselect(fdmax+1, &rdset, NULL, NULL, NULL, NULL) == -1) {
			if(errno == EINTR)
				continue;

			if(running)
				logfile.write(LOG_CRIT, "error: pselect() failure: %s", strerror(errno));
			
			break;
		}

		for(int current_socket = 0; current_socket <= fdmax; current_socket++) {
			if(!FD_ISSET(current_socket, &rdset))
			    continue;

			if(current_socket == main_socket) {
				socklen_t addrlen;
				struct sockaddr_storage clientaddr;

				addrlen = sizeof(clientaddr);
				memset(&clientaddr, 0, sizeof(clientaddr));
				int newfd = accept(current_socket, (struct sockaddr *)&clientaddr, &addrlen);

				if(newfd == -1) {
					logfile.write(LOG_ERR, "error: accept() failure");
				} else if(newfd >= FD_SETSIZE - 1) {
					close(newfd);
					logfile.write(LOG_ERR, "maximum fd reached, connection closed");
				} else {
					FD_SET(newfd, &refset);

					if (newfd > fdmax) {
						/* Keep track of the maximum */
						fdmax = newfd;
					}

					char hoststr[NI_MAXHOST]; 
					char portstr[NI_MAXSERV]; 

					int rc = getnameinfo((struct sockaddr *)&clientaddr, addrlen, hoststr, sizeof(hoststr), portstr, sizeof(portstr), NI_NUMERICHOST | NI_NUMERICSERV); 
					if(rc == 0)
						logfile.write(LOG_INFO, "[0x%02X] client connected from %s:%s", newfd, hoststr, portstr);
					else
						logfile.write(LOG_INFO, "[0x%02X] client connected", newfd);

					active_connections++;
				}
			} else {
				uint8_t query[MODBUS_TCP_MAX_ADU_LENGTH];
				modbus_set_socket(ctx, current_socket);
				int rc = modbus_receive(ctx, query);

				if (rc == -1 && errno != EMBBADCRC) {
					logfile.write(LOG_DEBUG, "[0x%02X] modbus connection closed: %s", current_socket, std::strerror(errno));
					close(current_socket);

					/* Remove from reference set */
					FD_CLR(current_socket, &refset);

					if(current_socket == fdmax)
						fdmax--;

					active_connections--;
				} else {
					std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
					if(modbus_reply(ctx, query, rc, mb_mapping) == -1)
						logfile.write(LOG_ERR, "[0x%02X] error sending modbus reply: %s", current_socket, std::strerror(errno));
				}
			}
		}

		bestsens::system_helper::systemd::status("active connections: " + std::to_string(active_connections));
	}

	running = false;

	/* wait on thread exit */
	aquire_inst.join();

	close(main_socket);
	modbus_mapping_free(mb_mapping);
	/* For RTU */
	modbus_close(ctx);
	modbus_free(ctx);

	logfile.write(LOG_DEBUG, "exited");

	return EXIT_SUCCESS;
}
