// Test.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "WhatBoys.h"

//#pragma comment(linker,"/subsystem:\"Windows\" /entry:\"mainCRTStartup\"")


int main(int /*argc*/, _TCHAR** /*argv*/)
{
    Beacon::WhatBoys    wb;
    wb.connect();
   
	return 0;
}

