#pragma once
#include <Windows.h>
#include <cstdint>
#include <random>


std::uint32_t	get_process_id() 
{
	return GetCurrentProcessId();
}

void	get_rand_bytes(std::uint8_t *buffer,int size)
{
	if (size < 0 || buffer == nullptr) 
	{
		return;
	}

	std::default_random_engine e(__rdtsc());
	//std::uniform_int_distribution<std::uint8_t> u(0, 0xff);
	for (int i = 0; i < size; i++) {
		buffer[i] = e();
	}
}

std::wstring s2ws(const std::string& str)
{
	std::wstring result;
	int len = MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.size(), NULL, 0);
	TCHAR* buffer = new TCHAR[len + 1];
	MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.size(), buffer, len);
	buffer[len] = '\0';
	result.append(buffer);
	delete[] buffer;
	return result;
}

std::uint32_t	get_local_ip()
{
	WSADATA WSAData;
	char hostName[256];
	if (!WSAStartup(MAKEWORD(2, 0), &WSAData))
	{
		if (!gethostname(hostName, sizeof(hostName)))
		{
	
			auto host = gethostbyname(hostName);
			if (host != NULL)
			{
				in_addr* addr = ((struct in_addr*)*host->h_addr_list);
				return addr->S_un.S_addr;
			}
		}
	}

}

BOOL IsRunasAdmin()
{
	BOOL bElevated = FALSE;
	HANDLE hToken = NULL;

	// Get current process token
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
		return FALSE;

	TOKEN_ELEVATION tokenEle;
	DWORD dwRetLen = 0;

	// Retrieve token elevation information
	if (GetTokenInformation(hToken, TokenElevation, &tokenEle, sizeof(tokenEle), &dwRetLen))
	{
		if (dwRetLen == sizeof(tokenEle))
		{
			bElevated = tokenEle.TokenIsElevated;
		}
	}

	CloseHandle(hToken);
	return bElevated;
}

bool	is_high_priv()
{
	return	IsRunasAdmin();
}

std::string	get_user_name()
{
	char* user = getenv("username");
	return std::string(user);
}

std::string	get_computer_name()
{
	char* n = getenv("userdomain");
	return std::string(n);
}

std::string get_process_name()
{
	char	buffer[MAX_PATH] = { 0 };
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	std::string path(buffer);
	auto pos = path.rfind('\\');
	if (pos != std::string::npos)
	{
		path = path.substr(pos+1);
	}
	return path;
}


bool	is_os_x64()
{
	SYSTEM_INFO si;
	GetNativeSystemInfo(&si);
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
		si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
		return TRUE;
	else
		return FALSE;
}

bool	is_process_x64()
{
#ifdef _WIN64
	return true;
#else
	return false;
#endif // 

}

void endian_swap(unsigned char* pData,int startIndex,int length)
{
	int i, cnt, end, start;
	cnt = length / 2;
	start = startIndex;
	end = startIndex + length - 1;
	std::uint8_t tmp;
	for (i = 0; i < cnt; i++)
	{
		tmp = pData[start + i];
		pData[start + i] = pData[end - i];
		pData[end - i] = tmp;
	}
}

__forceinline std::uint32_t	read_uint32(unsigned char* buf)
{
	unsigned char hex[4];
	for (int i = 0; i < 4; i++)
	{
		hex[i] = buf[i];
	}
	endian_swap(hex, 0, 4);
	return *((std::uint32_t*)hex);
}

__forceinline std::uint32_t	read_uint32_little(unsigned char* buf)
{
	unsigned char hex[4];
	for (int i = 0; i < 4; i++)
	{
		hex[i] = buf[i];
	}
	return *((std::uint32_t*)hex);
}


std::string subreplace(std::string resource_str, std::string sub_str, std::string new_str)
{
	std::string dst_str = resource_str;
	std::string::size_type pos = 0;
	while ((pos = dst_str.find(sub_str)) != std::string::npos)   //替换所有指定子串
	{
		dst_str.replace(pos, sub_str.length(), new_str);
	}
	return dst_str;
}




