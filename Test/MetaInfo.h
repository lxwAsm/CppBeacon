#pragma once
#include <cstdint>


typedef	struct system_info {
	std::uint32_t	client_id=0;
	std::uint32_t	process_id=0;
	std::uint16_t	ssh_port=0;
	std::uint8_t	meta_flag=0;
	std::uint8_t	major_ver=0;
	std::uint8_t	minor_ver=0;
	std::uint16_t	build_ver=0;
	std::uint32_t	func_addr=0;
	std::uint32_t	gmhb_addr=0;
	std::uint32_t	gpab_addr=0;
	std::uint32_t	loacl_ip=0;
}system_info;

struct MetaInfo
{
	std::uint32_t	magic = 0xBEEF;
	std::uint32_t	size;
	system_info		sys_info;
};