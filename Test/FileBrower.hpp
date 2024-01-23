#pragma once
#include <vector>
#include <string>
#include <sstream>
#include <Windows.h>

struct win_file
{

	std::string flag;
	std::uint32_t size;
	std::string time;
	std::string name;
	
};

__forceinline	std::string time2str(const FILETIME *write_time)
{
	SYSTEMTIME st;
	//FileTimeToLocalFileTime(&f_t.ftLastWriteTime, &f_t.ftLastWriteTime);
	//如果要有意义的明确显示，则转化为系统时间
	FileTimeToSystemTime(write_time, &st);
	std::stringstream	format_time;//02/01/2006 15:04:05
	format_time << st.wMonth << "/" << st.wDay << "/" << st.wYear << " " << st.wHour << ":" << st.wMinute << ":" << st.wSecond;
	return format_time.str();

}
std::vector<win_file>	list_file(const std::string& dir_name)
{

	std::vector<win_file> v;
	WIN32_FIND_DATAA fd{0};
	HANDLE hFind = ::FindFirstFileA(dir_name.c_str(), &fd);

	if (hFind != INVALID_HANDLE_VALUE)
	{
		win_file f_t;
		do {
			
			f_t.size = fd.nFileSizeLow;
			FileTimeToLocalFileTime(&fd.ftLastWriteTime, &fd.ftLastWriteTime);
			f_t.time = time2str(&fd.ftLastWriteTime);
			f_t.name = fd.cFileName;
			if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			{//非目录，即文件
				f_t.flag = "D";
			}
			else
			{
				f_t.flag = "F";
			}
			v.push_back(f_t);
		} while (::FindNextFileA(hFind, &fd));

		::FindClose(hFind);
	}
	return v;
}