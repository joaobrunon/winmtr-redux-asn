//*****************************************************************************
// FILE:            WinMTRGlobal.cpp
//
//
//*****************************************************************************

#include "WinMTRGlobal.h"
#include <stdio.h>

//*****************************************************************************
// gettimeofday
//
// win32 port of unix gettimeofday
//*****************************************************************************
/*
int gettimeofday(struct timeval* tv, struct timezone* / *tz* /)
{
   if(!tv)
      return -1;
   struct _timeb timebuffer;
   
   _ftime(&timebuffer);

   tv->tv_sec = (long)timebuffer.time;
   tv->tv_usec = timebuffer.millitm * 1000 + 500;
   return 0;
}// */

static void GetStartupLogPath(char* out, size_t size)
{
	if(!out || size == 0) return;
	char modulePath[MAX_PATH] = {};
	DWORD len = GetModuleFileNameA(NULL, modulePath, MAX_PATH);
	if(len == 0 || len >= MAX_PATH) {
		out[0] = '\0';
		return;
	}
	char* slash = strrchr(modulePath, '\\');
	if(slash) {
		*(slash + 1) = '\0';
	}
	snprintf(out, size, "%swinmtr_startup.log", modulePath);
}

void AppendStartupLog(const char* msg)
{
	char path[MAX_PATH + 64] = {};
	GetStartupLogPath(path, sizeof(path));
	if(path[0] == '\0') return;
	FILE* fp = fopen(path, "a");
	if(!fp) return;
	SYSTEMTIME st;
	GetLocalTime(&st);
	fprintf(fp, "%04u-%02u-%02u %02u:%02u:%02u.%03u %s\n",
		st.wYear, st.wMonth, st.wDay,
		st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
		msg ? msg : "");
	fclose(fp);
}
