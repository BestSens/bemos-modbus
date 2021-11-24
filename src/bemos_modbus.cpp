/*
 * modbus.cpp
 *
 *  Created on: 10.03.2017
 *	  Author: Jan Schöppach
 */

#include <arpa/inet.h>
#include <errno.h>
#include <execinfo.h>
#include <getopt.h>
#include <grp.h>
#include <modbus.h>
#include <pwd.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>

#include "bemos_modbus/version.hpp"
#include "cxxopts.hpp"
#include "nlohmann/json.hpp"
#include "spdlog/async.h"
#include "spdlog/fmt/bin_to_hex.h"
#include "spdlog/sinks/daily_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/spdlog.h"

#ifdef ENABLE_SYSTEMD_STATUS
#include "spdlog/sinks/systemd_sink.h"
#endif

#include "bone_helper/netHelper.hpp"
#include "bone_helper/loopTimer.hpp"
#include "bone_helper/jsonHelper.hpp"
#include "bone_helper/system_helper.hpp"

using namespace bestsens;

#define LOGIN_USER "bemos-analysis"
#define LOGIN_HASH "82e324d4dac1dacf019e498d6045835b3998def1c1cece4abf94a3743f149e208f30276b3275fdbb8c60dea4a042c490d73168d41cf70f9cdc3e1e62eb43f8e4"

namespace {
	constexpr auto MB_REGISTER_SIZE = 1024;
	constexpr auto NB_CONNECTION = 10;

	const json default_mb_register_map = {			
		{{"start address", 1}, {"type", "i32"}, {"source", "channel_data"}, {"attribute", "date"}, {"ignore oldness", true}},
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
		{{"start address", 27}, {"type", "float"}, {"source", "ks_data_0"}, {"attribute", "effective value"}, {"ignore oldness", true}},
		{{"start address", 29}, {"type", "float"}, {"source", "ks_data_1"}, {"attribute", "effective value"}, {"ignore oldness", true}},
		{{"start address", 31}, {"type", "float"}, {"source", "ks_data_2"}, {"attribute", "effective value"}, {"ignore oldness", true}},
		{{"start address", 33}, {"type", "float"}, {"source", "ks_data_3"}, {"attribute", "effective value"}, {"ignore oldness", true}},
		{{"start address", 35}, {"type", "float"}, {"source", "ks_data_4"}, {"attribute", "effective value"}, {"ignore oldness", true}},
		{{"start address", 37}, {"type", "float"}, {"source", "ks_data_5"}, {"attribute", "effective value"}, {"ignore oldness", true}},
		{{"start address", 39}, {"type", "float"}, {"source", "ks_data_6"}, {"attribute", "effective value"}, {"ignore oldness", true}},
		{{"start address", 41}, {"type", "float"}, {"source", "ks_data_7"}, {"attribute", "effective value"}, {"ignore oldness", true}}
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

	int main_socket = -1;

	#ifdef ENABLE_SYSTEMD_STATUS
	auto create_systemd_logger(std::string name = "") {
		std::vector<spdlog::sink_ptr> sinks;
		sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_st>());
		sinks.push_back(std::make_shared<spdlog::sinks::systemd_sink_st>());

		sinks[1]->set_pattern("%v");

		auto logger = std::make_shared<spdlog::async_logger>(name, begin(sinks), end(sinks), spdlog::thread_pool(), spdlog::async_overflow_policy::overrun_oldest);
		spdlog::register_logger(logger);
		return logger;
	}
	#endif

	void handle_signal(int signal) {
		switch(signal) {
			case SIGINT: 
			case SIGTERM: shutdown(main_socket, SHUT_RDWR);
						running = false;
						bestsens::loopTimer::kill_all();
						break;
			case SIGHUP: reload_config = true; break;
		}
	}

	std::vector<mb_map_config_t> update_configuration(bestsens::jsonNetHelper& socket, const std::string& map_file, std::vector<std::string>& source_list, std::vector<std::string>& identifier_list) {
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
						spdlog::warn("map_file loaded but invalid scheme");
					}
				} catch(const json::exception& e) {
					spdlog::warn("map_file set but error loading map data: {}", e.what());
				}
			} else {
				spdlog::error("map_file set but not found; using default map data");
			}
		}

		/*
		 * get register map from server when not loaded from file
		 */
		if(has_map_file == false) {
			json channel_attributes;
			if(socket.send_command("channel_attributes", channel_attributes, {{"name", "mb_register_map"}})) {
				spdlog::trace("mb_register_map: {}", channel_attributes.dump(2));

				if(is_json_array(channel_attributes, "payload") && channel_attributes["payload"].size() > 0)
					mb_register_map = channel_attributes["payload"];
			}

			if(!mb_register_map.size())
				mb_register_map = default_mb_register_map;
		}

		source_list.clear();
		identifier_list.clear();
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

				auto it = std::find(source_list.begin(), source_list.end(), temp.source);
				auto it2 = std::find(identifier_list.begin(), identifier_list.end(), temp.identifier);

				if(it == source_list.end())
					source_list.push_back(temp.source);

				if(it2 == identifier_list.end())
					identifier_list.push_back(temp.identifier);
			} catch(const std::exception& e) {
				spdlog::error("error adding register map: {}", e.what());
			}
		}

		return mb_map_config;
	}

	void setErrornous(uint16_t * start, ssize_t length) {
		for(ssize_t i = 0; i < length; i++)
			start[i] = 0x8000;
	}

	void addModbusValue(modbus_mapping_t * mb_mapping, const json& source, mb_map_config_t& config) {
		try {
			if(!is_json_object(source, config.source))
				throw std::runtime_error("source not found");

			int oldness = std::time(nullptr) - source.at(config.source).value("date", 0);
			if(oldness > 10 && !config.ignore_oldness)
				throw std::runtime_error("data too old");

			std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
			switch(config.type){
				case i16:
					{
						int16_t response = source.at(config.source).at(config.identifier).get<int16_t>();
						mb_mapping->tab_input_registers[config.start_address] = response;
						mb_mapping->tab_registers[config.start_address] = response;
					}
					break;
				case u16:
					{
						uint16_t response = source.at(config.source).at(config.identifier).get<uint16_t>();
						mb_mapping->tab_input_registers[config.start_address] = response;
						mb_mapping->tab_registers[config.start_address] = response;
					}
					break;
				case i32:
					{
						int32_t response = source.at(config.source).at(config.identifier).get<int32_t>();
						MODBUS_SET_INT32_TO_INT16(mb_mapping->tab_input_registers, config.start_address, response);
						MODBUS_SET_INT32_TO_INT16(mb_mapping->tab_registers, config.start_address, response);
					}
					break;
				case u32:
					{
						uint32_t response = source.at(config.source).at(config.identifier).get<uint32_t>();
						MODBUS_SET_INT32_TO_INT16(mb_mapping->tab_input_registers, config.start_address, response);
						MODBUS_SET_INT32_TO_INT16(mb_mapping->tab_registers, config.start_address, response);
					}
					break;
				case i64:
					{
						uint64_t response = source.at(config.source).at(config.identifier).get<uint64_t>();
						MODBUS_SET_INT64_TO_INT16(mb_mapping->tab_input_registers, config.start_address, response);
						MODBUS_SET_INT64_TO_INT16(mb_mapping->tab_registers, config.start_address, response);
					}
					break;
				case u64:
					{
						int64_t response = source.at(config.source).at(config.identifier).get<int64_t>();
						MODBUS_SET_INT64_TO_INT16(mb_mapping->tab_input_registers, config.start_address, response);
						MODBUS_SET_INT64_TO_INT16(mb_mapping->tab_registers, config.start_address, response);
					}
					break;
				case float32:
					{
						float response = source.at(config.source).at(config.identifier).get<float>();
						modbus_set_float_badc(response, mb_mapping->tab_input_registers + config.start_address);
						modbus_set_float_badc(response, mb_mapping->tab_registers + config.start_address);
					}
					break;
				default: throw std::runtime_error("type not found"); break;
			}

			mb_mapping->tab_input_bits[config.start_address] = 1;

			config.map_error_displayed = false;
		} catch(const std::exception& e) {
			if(config.map_error_displayed == false) {
				spdlog::error("error setting map data for 0x{:04X} ({}.{}): {}", config.start_address, config.source, config.identifier, e.what());
				config.map_error_displayed = true;
			}

			std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
			switch(config.type){
				case i16:
				case u16:
					setErrornous(mb_mapping->tab_input_registers + config.start_address, 1);
					setErrornous(mb_mapping->tab_registers + config.start_address, 1);
					break;
				case i32:
				case u32:
					setErrornous(mb_mapping->tab_input_registers + config.start_address, 2);
					setErrornous(mb_mapping->tab_registers + config.start_address, 2);
					break;
				case i64:
				case u64:
					setErrornous(mb_mapping->tab_input_registers + config.start_address, 4);
					setErrornous(mb_mapping->tab_registers + config.start_address, 4);
					break;
				case float32:
					float err = NAN;
					modbus_set_float_badc(err, mb_mapping->tab_input_registers + config.start_address);
					modbus_set_float_badc(err, mb_mapping->tab_registers + config.start_address);
					break;
			}

			mb_mapping->tab_input_bits[config.start_address] = 0;
		}
	}

	auto get_uid(const std::string& user_name) -> unsigned int {
		struct passwd *pwd = getpwnam(user_name.c_str());

		if (pwd == nullptr)
			throw std::runtime_error(fmt::format("error getting uid: {}", strerror(errno)));
		
		return static_cast<unsigned int>(pwd->pw_uid);
	}

	auto get_gid(const std::string& group_name) -> unsigned int {
		struct group *grp = getgrnam(group_name.c_str());

		if (grp == nullptr)
			throw std::runtime_error(fmt::format("error getting gid: {}", strerror(errno)));

		return static_cast<unsigned int>(grp->gr_gid);
	}

	auto drop_priviledges() -> bool {
		try {
			auto userid = get_uid("bemos");
			auto groupid = get_gid("bemos_users");

			if (setgid(groupid) != 0)
				throw std::runtime_error(fmt::format("setgid: Unable to drop group privileges: {}", strerror(errno)));

			if (setuid(userid) != 0)
				throw std::runtime_error(fmt::format("setuid: Unable to drop user privileges: {}", strerror(errno)));

			if (setuid(0) != -1) 
				throw std::runtime_error("managed to regain root privileges");
		} catch (const std::exception& e) {
			spdlog::error("error dropping privileges: {}", e.what());
			return false;
		}

		return true;
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
		if(!running)
			break;

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

		spdlog::info("connected to BeMoS");

		try {
			bestsens::loopTimer dataTimer(std::chrono::seconds(1), 0);

			/*
			 * register "external_data" algo
			 */
			if(ext_amount > 0 || coil_amount > 0) {
				json j;
				socket.send_command("register_analysis", j, {{"name", "external_data"}});

				if(coil_amount > 0)
					socket.send_command("register_analysis", j, {{"name", "active_coils"}});
			}

			while(running) {
				dataTimer.wait_on_tick();
				if(!running)
					break;

				if(reload_config) {
					mb_map_config = update_configuration(socket, map_file, source_list, identifier_list);

					spdlog::info("configuration reloaded");

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
					spdlog::trace("{}", channel_data.dump(2));

					if(is_json_object(channel_data, "payload")) {
						const json payload = channel_data.at("payload");

						try {
							int new_ts = payload.at("ack").at("date").get<int>();

							if(new_ts != ack.ts) {
								ack.id = payload.at("ack").at("ack").get<int>();
								ack.ts = payload.at("ack").at("date").get<int>();
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
								addModbusValue(mb_mapping, payload, element);
							} catch(const std::exception& e) {
								spdlog::warn("error reading element of register map: {}", e.what());
								continue;
							}
						}
					} else {
						spdlog::error("error retrieving data");
						break;
					}
				}

				json active_coils = {
					{"name", "active_coils"}
				};

				if(socket.send_command("channel_data", channel_data, {{"name", "active_coils"}}, 2)) {
					spdlog::trace("{}", channel_data.dump(2));

					if(is_json_object(channel_data, "payload")) {
						const json payload = channel_data.at("payload");

						try {
							if(is_json_object(payload, "active_coils")) {
								active_coils["data"] = payload.at("active_coils");

								if(active_coils["data"].count("date"))
									active_coils["data"].erase("date");
							}
						} catch(...) {}
					}
				}
				
				try {
					json payload = {
						{"name", "external_data"}
					};

					if(ext_amount > 0) {
						std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);

						for(unsigned int i = 0; i < ext_amount * 2; i++) 
							mb_mapping->tab_input_registers[100 + i] = mb_mapping->tab_registers[100 + i];

						for(unsigned int i = 0; i < ext_amount; i++)
							payload["data"]["ext_" + std::to_string(i + 1)] = modbus_get_float_abcd(mb_mapping->tab_registers + 100 + i * 2);
					}

					if(coil_amount > 0) {
						std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
						
						for(unsigned int i = 0; i < coil_amount; i++) {
							bool coil_state = mb_mapping->tab_bits[i];

							const std::string coil_name("coil_" + std::to_string(i + 1));

							payload["data"][coil_name] = coil_state;

							if(!coil_state) {
								if(active_coils["data"].count(coil_name))
									active_coils["data"].erase(coil_name);
							} else {
								if(active_coils["data"].count(coil_name) == 0 || ack.id == static_cast<int>(i) + 1)
									active_coils["data"][coil_name] = std::time(nullptr);
							}
						}

						json j;
						socket.send_command("new_data", j, active_coils);
					}

					json j;
					socket.send_command("new_data", j, payload);
				} catch(const std::exception &e) {
					spdlog::error("error parsing external data: {}", e.what());
				}
			}
		} catch(const std::exception &e) {
			spdlog::error("exception: {}", e.what());
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

	unsigned int coil_amount = 0;
	unsigned int ext_amount = 0;

	std::string conn_target = "localhost";
	std::string conn_port = "6450";
	std::string username = std::string(LOGIN_USER);
	std::string password = std::string(LOGIN_HASH);

	std::string map_file = "";

	auto console = spdlog::stdout_color_mt<spdlog::async_factory>("console");
	console->set_pattern("%v");

	#ifdef ENABLE_SYSTEMD_STATUS
	auto systemd_logger = create_systemd_logger("bemos_modbus");
	systemd_logger->flush_on(spdlog::level::err); 
	spdlog::set_default_logger(systemd_logger);
	#else
	auto stdout_logger = spdlog::stdout_color_mt<spdlog::async_factory>("bemos_modbus");
	stdout_logger->flush_on(spdlog::level::err); 
	spdlog::set_default_logger(stdout_logger);
	#endif

	spdlog::flush_every(std::chrono::seconds(5));

	/*
	 * parse commandline options
	 */
	{
		cxxopts::Options options("bemos_modbus", "BeMoS one modbus application");

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
				spdlog::get("console")->info(options.help());
				return EXIT_SUCCESS;
			}

			if(result.count("version")) {
				spdlog::get("console")->info("bemos-modbus version: {}", appVersion());

				if (result.count("verbose") != 0u) {
					spdlog::get("console")->info("git branch: {}", appGitBranch());
					spdlog::get("console")->info("git revision: {}", appGitRevision());
					spdlog::get("console")->info("compiled @ {}", appCompileDate());
					spdlog::get("console")->info("compiler version: {}", appCompilerVersion());
				}

				return EXIT_SUCCESS;
			}

			if(daemon) {
				#ifdef ENABLE_SYSTEMD_STATUS
				if(systemd_logger->sinks().size() > 1)
					systemd_logger->sinks().erase(systemd_logger->sinks().begin());
				#endif

				spdlog::info("daemonized");
			}

			if(result.count("suppress_syslog")) {
				#ifdef ENABLE_SYSTEMD_STATUS
				if(systemd_logger->sinks().size() > 1)
					systemd_logger->sinks().erase(systemd_logger->sinks().begin());
				#endif
			}

			if(result.count("verbose")) {
				spdlog::set_level(spdlog::level::debug);
				spdlog::info("verbose output enabled");
			}

			if(result.count("verbose") > 1) {
				spdlog::set_level(spdlog::level::trace);
				spdlog::info("trace output enabled");
			}

			if(result.count("password")) {
				password = bestsens::netHelper::sha512(result["password"].as<std::string>());
			}

			if(result.count("map_file")) {
				spdlog::info("map file set to {}", map_file);
			}

			if(result.count("timeout")) {
				spdlog::info("modbus timeout set to {} us", mb_to_usec);
			}
		} catch(const std::exception& e) {
			spdlog::get("console")->error(e.what());
			return EXIT_FAILURE;
		}
	}

	if(coil_amount > MB_REGISTER_SIZE)
		coil_amount = MB_REGISTER_SIZE;

	if(ext_amount > (MB_REGISTER_SIZE - 100) / 2)
		ext_amount = (MB_REGISTER_SIZE - 100) / 2;

	spdlog::info("starting bemos-modbus {}", appVersion());
	spdlog::info("generating {} coils", coil_amount);
	spdlog::info("generating {} ext values", ext_amount);

	/*
	 * Test IEEE 754
	 */
	if(!std::numeric_limits<float>::is_iec559)
		spdlog::warn("application wasn't compiled with IEEE 754 standard, floating point values may be out of standard");
	
	ctx = modbus_new_tcp_pi("::0", port.c_str());
	
	if(ctx == NULL) {
		spdlog::critical("Unable to allocate libmodbus context: {}", modbus_strerror(errno));
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
		spdlog::critical("Failed to allocate the mapping: {}", modbus_strerror(errno));
		modbus_free(ctx);
		return EXIT_FAILURE;
	}

	main_socket = modbus_tcp_pi_listen(ctx, NB_CONNECTION);

	if(main_socket == -1) {
		spdlog::critical("cannot reserve port {}, exiting", port);
		modbus_mapping_free(mb_mapping);
		/* For RTU */
		modbus_close(ctx);
		modbus_free(ctx);
		return EXIT_FAILURE;
	}

	spdlog::info("listening on port {}", port);

	if(getuid() == 0) {
		/* process is running as root, drop privileges */
		spdlog::info("running as root, dropping privileges");

		if (!drop_priviledges()) {
			spdlog::critical("dropping of privileges failed!");
			return EXIT_FAILURE;
		}
	}

	/* spawn aquire thread */ 
	std::thread aquire_inst(data_aquisition, conn_target, conn_port, username, password, mb_mapping, map_file, coil_amount, ext_amount);

	/* Deamonize */
	if(daemon) {
		bestsens::system_helper::daemonize();
		spdlog::info("daemon created");
	} else {
		spdlog::debug("skipped daemonizing");
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

	spdlog::info("waiting for connection...");

	while(running) {
		fd_set rdset = refset;
		if(fdmax >= FD_SETSIZE - 1) {
			spdlog::critical("error: maximum fd reached");
			break;
		}

		if(pselect(fdmax+1, &rdset, NULL, NULL, NULL, NULL) == -1) {
			if(errno == EINTR)
				continue;

			if(running)
				spdlog::critical("error: pselect() failure: {}", strerror(errno));
			
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
					spdlog::error("error: accept() failure");
				} else if(newfd >= FD_SETSIZE - 1) {
					close(newfd);
					spdlog::error("maximum fd reached, connection closed");
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
						spdlog::info("[0x{:02X}] client connected from {}:{}", newfd, hoststr, portstr);
					else
						spdlog::info("[0x{:02X}] client connected", newfd);

					active_connections++;
				}
			} else {
				uint8_t query[MODBUS_TCP_MAX_ADU_LENGTH];
				modbus_set_socket(ctx, current_socket);
				int rc = modbus_receive(ctx, query);

				if (rc == -1 && errno != EMBBADCRC) {
					spdlog::debug("[0x{:02X}] modbus connection closed: {}", current_socket, std::strerror(errno));
					close(current_socket);

					/* Remove from reference set */
					FD_CLR(current_socket, &refset);

					if(current_socket == fdmax)
						fdmax--;

					active_connections--;
				} else {
					std::lock_guard<std::mutex> lock(mb_mapping_access_mtx);
					if(modbus_reply(ctx, query, rc, mb_mapping) == -1)
						spdlog::error("[0x{:02X}] error sending modbus reply: {}", current_socket, std::strerror(errno));
				}
			}
		}

		bestsens::system_helper::systemd::status(fmt::format("active connections: {}", active_connections));
	}

	running = false;

	/* wait on thread exit */
	aquire_inst.join();

	close(main_socket);
	modbus_mapping_free(mb_mapping);
	/* For RTU */
	modbus_close(ctx);
	modbus_free(ctx);

	spdlog::debug("exited");

	return EXIT_SUCCESS;
}
