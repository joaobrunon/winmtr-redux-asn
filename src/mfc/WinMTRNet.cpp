//*****************************************************************************
// FILE:            WinMTRNet.cpp
//
//*****************************************************************************
#include <winsock2.h>
#include <ws2tcpip.h>
#include "WinMTRGlobal.h"
#include "WinMTRNet.h"
#include "WinMTRDialog.h"
#include <iostream>
#include <sstream>
#include <array>
#include <cstring>
#include <cmath>
#include <string>

#ifdef _DEBUG
#	define TRACE_MSG(msg)										\
	{															\
		std::ostringstream dbg_msg(std::ostringstream::out);	\
		dbg_msg << msg << std::endl;							\
		OutputDebugString(dbg_msg.str().c_str());				\
	}
#else
#	define TRACE_MSG(msg)
#endif

#define IPFLAG_DONT_FRAGMENT	0x02
#define MAX_HOPS				MaxHost

struct trace_thread {
	WinMTRNet*	winmtr;
	in_addr		address;
	int			ttl;
};
struct trace_thread6 {
	WinMTRNet*		winmtr;
	sockaddr_in6	address;
	int				ttl;
};

struct dns_resolver_thread {
	WinMTRNet*	winmtr;
	int			index;
};

unsigned WINAPI TraceThread(void* p);
unsigned WINAPI TraceThread6(void* p);
void DnsResolverThread(void* p);

static bool ParseIcmpTimeExceeded(const unsigned char* buffer, int length, unsigned short expectedPort)
{
	if(length < 28) return false;
	unsigned char ipHeaderLen = (buffer[0] & 0x0F) * 4;
	if(length < ipHeaderLen + 8) return false;
	unsigned char icmpType = buffer[ipHeaderLen];
	if(icmpType != 11 && icmpType != 3) return false;
	const unsigned char* innerIp = buffer + ipHeaderLen + 8;
	if(innerIp + 20 > buffer + length) return false;
	unsigned char innerHeaderLen = (innerIp[0] & 0x0F) * 4;
	if(innerIp + innerHeaderLen + 8 > buffer + length) return false;
	if(innerIp[9] != IPPROTO_TCP) return false;
	const unsigned char* tcpHeader = innerIp + innerHeaderLen;
	unsigned short destPortNet = 0;
	memcpy(&destPortNet, tcpHeader + 2, sizeof(destPortNet));
	unsigned short destPort = ntohs(destPortNet);
	return destPort == expectedPort;
}

static void CopyToBuffer(char* dst, size_t size, const std::string& src)
{
	if(size == 0) return;
	std::strncpy(dst, src.c_str(), size - 1);
	dst[size - 1] = '\0';
}

static int ParseIcmpUdp(const unsigned char* buffer, int length, unsigned short expectedPort)
{
	if(length < 28) return 0;
	unsigned char ipHeaderLen = (buffer[0] & 0x0F) * 4;
	if(length < ipHeaderLen + 8) return 0;
	unsigned char icmpType = buffer[ipHeaderLen];
	unsigned char icmpCode = buffer[ipHeaderLen + 1];
	if(icmpType != 11 && icmpType != 3) return 0;
	const unsigned char* innerIp = buffer + ipHeaderLen + 8;
	if(innerIp + 20 > buffer + length) return 0;
	unsigned char innerHeaderLen = (innerIp[0] & 0x0F) * 4;
	if(innerIp + innerHeaderLen + 8 > buffer + length) return 0;
	if(innerIp[9] != IPPROTO_UDP) return 0;
	const unsigned char* udpHeader = innerIp + innerHeaderLen;
	unsigned short destPortNet = 0;
	memcpy(&destPortNet, udpHeader + 2, sizeof(destPortNet));
	unsigned short destPort = ntohs(destPortNet);
	if(destPort != expectedPort) return 0;
	if(icmpType == 3 && icmpCode == 3) return 2; // port unreachable
	return 1; // time exceeded or other unreachable
}

WinMTRNet::WinMTRNet(WinMTRDialog* wp)
{
	AppendStartupLog("WinMTRNet ctor start");

	ghMutex = CreateMutex(NULL, FALSE, NULL);
	hasIPv6=true;
	tracing=false;
	initialized = false;
	wmtrdlg = wp;
	WSADATA wsaData;
	
	if(WSAStartup(MAKEWORD(2, 2), &wsaData)) {
		AfxMessageBox(IDS_ERR_INIT_SOCKETS);
		AppendStartupLog("WinMTRNet WSAStartup failed");
		return;
	}
	OSVERSIONINFOEX osvi= {0};
	osvi.dwOSVersionInfoSize=sizeof(OSVERSIONINFOEX);
	if(!GetVersionEx((OSVERSIONINFO*) &osvi)) {
		AfxMessageBox(IDS_ERR_WIN_VERSION);
		AppendStartupLog("WinMTRNet GetVersionEx failed");
		return;
	}
	if(osvi.dwMajorVersion==5 && osvi.dwMinorVersion==0) { //w2k
		hICMP_DLL=LoadLibrary(_T("ICMP.DLL"));
		if(!hICMP_DLL) {
			AfxMessageBox(IDS_ERR_ICMP_DLL);
			AppendStartupLog("WinMTRNet LoadLibrary ICMP.DLL failed");
			return;
		}
	} else {
		hICMP_DLL=LoadLibrary(_T("Iphlpapi.dll"));
		if(!hICMP_DLL) {
			AfxMessageBox(IDS_ERR_IPHLPAPI_DLL);
			AppendStartupLog("WinMTRNet LoadLibrary Iphlpapi.dll failed");
			return;
		}
	}
	
	/*
	 * Get pointers to ICMP.DLL functions
	 */
	//IPv4
	lpfnIcmpCreateFile  = (LPFNICMPCREATEFILE)GetProcAddress(hICMP_DLL,"IcmpCreateFile");
	lpfnIcmpCloseHandle = (LPFNICMPCLOSEHANDLE)GetProcAddress(hICMP_DLL,"IcmpCloseHandle");
	lpfnIcmpSendEcho2   = (LPFNICMPSENDECHO2)GetProcAddress(hICMP_DLL,"IcmpSendEcho2");
	if(!lpfnIcmpCreateFile || !lpfnIcmpCloseHandle || !lpfnIcmpSendEcho2) {
		AfxMessageBox(IDS_ERR_ICMP_LIB);
		AppendStartupLog("WinMTRNet IcmpCreate/Close/Send missing");
		return;
	}
	//IPv6
	lpfnIcmp6CreateFile=(LPFNICMP6CREATEFILE)GetProcAddress(hICMP_DLL,"Icmp6CreateFile");
	lpfnIcmp6SendEcho2=(LPFNICMP6SENDECHO2)GetProcAddress(hICMP_DLL,"Icmp6SendEcho2");
	if(!lpfnIcmp6CreateFile || !lpfnIcmp6SendEcho2) {
		hasIPv6=false;
		AfxMessageBox(IDS_ERR_IPV6_SUPPORT);
		AppendStartupLog("WinMTRNet IPv6 ICMP not found");
	}
	
	/*
	 * IcmpCreateFile() - Open the ping service
	 */
	hICMP = (HANDLE) lpfnIcmpCreateFile();
	if(hICMP == INVALID_HANDLE_VALUE) {
		AfxMessageBox(IDS_ERR_ICMP_MODULE);
		AppendStartupLog("WinMTRNet IcmpCreateFile failed");
		return;
	}
	if(hasIPv6) {
		hICMP6=(HANDLE)lpfnIcmp6CreateFile();
		if(hICMP6==INVALID_HANDLE_VALUE) {
			AfxMessageBox(IDS_ERR_ICMPV6_MODULE);
			hasIPv6=false;
			AppendStartupLog("WinMTRNet Icmp6CreateFile failed");
		}
	}
	
	ResetHops();
	
	initialized = true;
	AppendStartupLog("WinMTRNet ctor ok");
	return;
}

WinMTRNet::~WinMTRNet()
{
	if(initialized) {
		/*
		 * IcmpCloseHandle - Close the ICMP handle
		 */
		if(hasIPv6) lpfnIcmpCloseHandle(hICMP6);
		lpfnIcmpCloseHandle(hICMP);
		
		// Shut down...
		FreeLibrary(hICMP_DLL);
		
		WSACleanup();
		
		CloseHandle(ghMutex);
	}
}

void WinMTRNet::ResetHops()
{
	memset(host,0,sizeof(host));
}

void WinMTRNet::DoTrace(sockaddr* addr)
{
	HANDLE hThreads[MAX_HOPS];
	unsigned char hops=0;
	int maxHops = wmtrdlg->maxHops;
	if(maxHops <= 0) maxHops = DEFAULT_MAX_HOPS;
	if(maxHops > MAX_HOPS) maxHops = MAX_HOPS;
	int firstTtl = wmtrdlg->firstTtl;
	if(firstTtl <= 0) firstTtl = 1;
	if(firstTtl > maxHops) firstTtl = maxHops;
	tracing = true;
	ResetHops();
	if(addr->sa_family==AF_INET6) {
		host[0].addr6.sin6_family=AF_INET6;
		last_remote_addr6=((sockaddr_in6*)addr)->sin6_addr;
		for(int ttl = firstTtl; ttl <= maxHops; ++ttl) {// one thread per TTL value
			trace_thread6* current=new trace_thread6;
			current->address=*(sockaddr_in6*)addr;
			current->winmtr=this;
			current->ttl=ttl;
			hThreads[hops]=(HANDLE)_beginthreadex(NULL,0,TraceThread6,current,0,NULL);
			Sleep(30);
			if(++hops>this->GetMax()) break;
		}
	} else {
		host[0].addr.sin_family=AF_INET;
		last_remote_addr=((sockaddr_in*)addr)->sin_addr;
		for(int ttl = firstTtl; ttl <= maxHops; ++ttl) {// one thread per TTL value
			trace_thread* current=new trace_thread;
			current->address=((sockaddr_in*)addr)->sin_addr;
			current->winmtr=this;
			current->ttl=ttl;
			hThreads[hops]=(HANDLE)_beginthreadex(NULL,0,TraceThread,current,0,NULL);
			Sleep(30);
			if(++hops>this->GetMax()) break;
		}
	}
	WaitForMultipleObjects(hops, hThreads, TRUE, INFINITE);
	for(; hops;) CloseHandle(hThreads[--hops]);
}

void WinMTRNet::DoTraceTcp(sockaddr_in* addr)
{
	if(!addr) return;
	ResetHops();
	tracing = true;
	host[0].addr.sin_family = AF_INET;
	last_remote_addr = addr->sin_addr;

	int maxHops = wmtrdlg->maxHops;
	if(maxHops <= 0) maxHops = DEFAULT_MAX_HOPS;
	if(maxHops > MAX_HOPS) maxHops = MAX_HOPS;
	int firstTtl = wmtrdlg->firstTtl;
	if(firstTtl <= 0) firstTtl = 1;
	if(firstTtl > maxHops) firstTtl = maxHops;

	SOCKET icmpSock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(icmpSock == INVALID_SOCKET) {
		AfxMessageBox(IDS_ERR_ICMP_TCP_SOCKET);
		tracing = false;
		return;
	}

	sockaddr_in destAddr = *addr;
	unsigned short destPort = static_cast<unsigned short>(wmtrdlg->port);
	if(destPort == 0) destPort = DEFAULT_PORT;
	destAddr.sin_port = htons(destPort);

	int finalHop = -1;
	while(tracing) {
		for(int ttl = firstTtl; ttl <= maxHops; ++ttl) {
			if(!tracing) break;
			while(wmtrdlg->paused && tracing) {
				Sleep(100);
			}

			if(finalHop > 0 && ttl > finalHop) break;

			AddXmit(ttl - 1);

			SOCKET tcpSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if(tcpSock == INVALID_SOCKET) {
				continue;
			}

			if(wmtrdlg->tos >= 0) {
				int tos = wmtrdlg->tos;
				setsockopt(tcpSock, IPPROTO_IP, IP_TOS, reinterpret_cast<const char*>(&tos), sizeof(tos));
			}

			if(wmtrdlg->localPort >= 0) {
				sockaddr_in bindAddr{};
				bindAddr.sin_family = AF_INET;
				bindAddr.sin_port = htons(static_cast<unsigned short>(wmtrdlg->localPort));
				bindAddr.sin_addr.s_addr = htonl(INADDR_ANY);
				bind(tcpSock, reinterpret_cast<sockaddr*>(&bindAddr), sizeof(bindAddr));
			}

			int ttlVal = ttl;
			setsockopt(tcpSock, IPPROTO_IP, IP_TTL, reinterpret_cast<const char*>(&ttlVal), sizeof(ttlVal));

			u_long nonBlocking = 1;
			ioctlsocket(tcpSock, FIONBIO, &nonBlocking);

			DWORD startTick = GetTickCount();
			connect(tcpSock, reinterpret_cast<sockaddr*>(&destAddr), sizeof(destAddr));

			bool gotReply = false;
			sockaddr_in replyAddr{};
			int rtt = 0;

			while(true) {
				DWORD nowTick = GetTickCount();
				DWORD elapsed = nowTick - startTick;
				if(elapsed >= static_cast<DWORD>(wmtrdlg->timeoutMs)) {
					break;
				}
				int remainingMs = wmtrdlg->timeoutMs - static_cast<int>(elapsed);
				timeval tv{};
				tv.tv_sec = remainingMs / 1000;
				tv.tv_usec = (remainingMs % 1000) * 1000;

				fd_set readfds;
				fd_set writefds;
				FD_ZERO(&readfds);
				FD_ZERO(&writefds);
				FD_SET(icmpSock, &readfds);
				FD_SET(tcpSock, &writefds);

				int ready = select(0, &readfds, &writefds, NULL, &tv);
				if(ready <= 0) break;

				if(FD_ISSET(icmpSock, &readfds)) {
					unsigned char buffer[512];
					sockaddr_in fromAddr{};
					int fromLen = sizeof(fromAddr);
					int recvLen = recvfrom(icmpSock, reinterpret_cast<char*>(buffer), sizeof(buffer), 0, reinterpret_cast<sockaddr*>(&fromAddr), &fromLen);
					if(recvLen > 0 && ParseIcmpTimeExceeded(buffer, recvLen, destPort)) {
						rtt = static_cast<int>(GetTickCount() - startTick);
						replyAddr = fromAddr;
						gotReply = true;
						break;
					}
				}

				if(FD_ISSET(tcpSock, &writefds)) {
					int soError = 0;
					int len = sizeof(soError);
					getsockopt(tcpSock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soError), &len);
					rtt = static_cast<int>(GetTickCount() - startTick);
					if(soError == 0 || soError == WSAECONNREFUSED) {
						replyAddr = destAddr;
						gotReply = true;
						if(finalHop <= 0) finalHop = ttl;
					}
					break;
				}
			}

			closesocket(tcpSock);

			if(gotReply) {
				UpdateRTT(ttl - 1, rtt);
				AddReturned(ttl - 1);
				SetAddr(ttl - 1, replyAddr.sin_addr.s_addr);
			}

			Sleep(30);
		}

		if(!tracing) break;
		Sleep(static_cast<DWORD>(wmtrdlg->interval * 1000));
	}

	closesocket(icmpSock);
}

void WinMTRNet::DoTraceUdp(sockaddr_in* addr)
{
	if(!addr) return;
	ResetHops();
	tracing = true;
	host[0].addr.sin_family = AF_INET;
	last_remote_addr = addr->sin_addr;

	int maxHops = wmtrdlg->maxHops;
	if(maxHops <= 0) maxHops = DEFAULT_MAX_HOPS;
	if(maxHops > MAX_HOPS) maxHops = MAX_HOPS;
	int firstTtl = wmtrdlg->firstTtl;
	if(firstTtl <= 0) firstTtl = 1;
	if(firstTtl > maxHops) firstTtl = maxHops;

	SOCKET icmpSock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(icmpSock == INVALID_SOCKET) {
		AfxMessageBox(IDS_ERR_ICMP_UDP_SOCKET);
		tracing = false;
		return;
	}

	SOCKET udpSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(udpSock == INVALID_SOCKET) {
		closesocket(icmpSock);
		AfxMessageBox(IDS_ERR_UDP_SOCKET);
		tracing = false;
		return;
	}

	if(wmtrdlg->tos >= 0) {
		int tos = wmtrdlg->tos;
		setsockopt(udpSock, IPPROTO_IP, IP_TOS, reinterpret_cast<const char*>(&tos), sizeof(tos));
	}

	if(wmtrdlg->localPort >= 0) {
		sockaddr_in bindAddr{};
		bindAddr.sin_family = AF_INET;
		bindAddr.sin_port = htons(static_cast<unsigned short>(wmtrdlg->localPort));
		bindAddr.sin_addr.s_addr = htonl(INADDR_ANY);
		bind(udpSock, reinterpret_cast<sockaddr*>(&bindAddr), sizeof(bindAddr));
	}

	int finalHop = -1;
	while(tracing) {
		for(int ttl = firstTtl; ttl <= maxHops; ++ttl) {
			if(!tracing) break;
			while(wmtrdlg->paused && tracing) {
				Sleep(100);
			}

			if(finalHop > 0 && ttl > finalHop) break;

			AddXmit(ttl - 1);

			int ttlVal = ttl;
			setsockopt(udpSock, IPPROTO_IP, IP_TTL, reinterpret_cast<const char*>(&ttlVal), sizeof(ttlVal));

			sockaddr_in destAddr = *addr;
			unsigned short destPort = static_cast<unsigned short>(wmtrdlg->port);
			if(destPort == 0) {
				destPort = static_cast<unsigned short>(33434 + ttl);
			}
			destAddr.sin_port = htons(destPort);

			char payload[512];
			int payloadSize = wmtrdlg->pingsize;
			if(payloadSize < 1) payloadSize = 1;
			if(payloadSize > static_cast<int>(sizeof(payload))) payloadSize = sizeof(payload);
			memset(payload, 0x42, payloadSize);
			if(wmtrdlg->bitPattern >= 0) {
				int pattern = wmtrdlg->bitPattern;
				if(pattern > 255) pattern = rand() % 256;
				memset(payload, pattern, payloadSize);
			}

			DWORD startTick = GetTickCount();
			sendto(udpSock, payload, payloadSize, 0, reinterpret_cast<sockaddr*>(&destAddr), sizeof(destAddr));

			bool gotReply = false;
			sockaddr_in replyAddr{};
			int rtt = 0;
			bool reachedDest = false;

			while(true) {
				DWORD nowTick = GetTickCount();
				DWORD elapsed = nowTick - startTick;
				if(elapsed >= static_cast<DWORD>(wmtrdlg->timeoutMs)) {
					break;
				}
				int remainingMs = wmtrdlg->timeoutMs - static_cast<int>(elapsed);
				timeval tv{};
				tv.tv_sec = remainingMs / 1000;
				tv.tv_usec = (remainingMs % 1000) * 1000;

				fd_set readfds;
				FD_ZERO(&readfds);
				FD_SET(icmpSock, &readfds);

				int ready = select(0, &readfds, NULL, NULL, &tv);
				if(ready <= 0) break;

				if(FD_ISSET(icmpSock, &readfds)) {
					unsigned char buffer[512];
					sockaddr_in fromAddr{};
					int fromLen = sizeof(fromAddr);
					int recvLen = recvfrom(icmpSock, reinterpret_cast<char*>(buffer), sizeof(buffer), 0, reinterpret_cast<sockaddr*>(&fromAddr), &fromLen);
					if(recvLen > 0) {
						int match = ParseIcmpUdp(buffer, recvLen, destPort);
						if(match > 0) {
							rtt = static_cast<int>(GetTickCount() - startTick);
							replyAddr = fromAddr;
							gotReply = true;
							reachedDest = (match == 2);
							break;
						}
					}
				}
			}

			if(gotReply) {
				UpdateRTT(ttl - 1, rtt);
				AddReturned(ttl - 1);
				SetAddr(ttl - 1, replyAddr.sin_addr.s_addr);
				if(reachedDest && finalHop <= 0) finalHop = ttl;
			}

			Sleep(30);
		}

		if(!tracing) break;
		Sleep(static_cast<DWORD>(wmtrdlg->interval * 1000));
	}

	closesocket(udpSock);
	closesocket(icmpSock);
}

void WinMTRNet::StopTrace()
{
	tracing = false;
}

unsigned WINAPI TraceThread(void* p)
{
	trace_thread* current = (trace_thread*)p;
	WinMTRNet* wmtrnet = current->winmtr;
	TRACE_MSG("Thread with TTL=" << (int)current->ttl << " started.");
	
	IPINFO			stIPInfo, *lpstIPInfo;
	char			achReqData[8192];
	WORD			nDataLen = wmtrnet->wmtrdlg->pingsize;
	union {
		ICMP_ECHO_REPLY icmp_echo_reply;
		char achRepData[sizeof(ICMPECHO)+8192];
	};
	
	lpstIPInfo				= &stIPInfo;
	stIPInfo.Ttl			= (UCHAR)current->ttl;
	stIPInfo.Tos			= (wmtrnet->wmtrdlg->tos >= 0) ? (UCHAR)wmtrnet->wmtrdlg->tos : 0;
	stIPInfo.Flags			= IPFLAG_DONT_FRAGMENT;
	stIPInfo.OptionsSize	= 0;
	stIPInfo.OptionsData	= NULL;
	for(int i=0; i<nDataLen; ++i) achReqData[i]=32;//whitespaces
	if(wmtrnet->wmtrdlg->bitPattern >= 0) {
		int pattern = wmtrnet->wmtrdlg->bitPattern;
		if(pattern > 255) pattern = rand() % 256;
		memset(achReqData, pattern, nDataLen);
	}
	while(wmtrnet->tracing) {
		while(wmtrnet->wmtrdlg->paused && wmtrnet->tracing) {
			Sleep(100);
		}
		// For some strange reason, ICMP API is not filling the TTL for icmp echo reply
		// Check if the current thread should be closed
		if(current->ttl > wmtrnet->GetMax()) break;
		// NOTE: some servers does not respond back everytime, if TTL expires in transit; e.g. :
		// ping -n 20 -w 5000 -l 64 -i 7 www.chinapost.com.tw  -> less that half of the replies are coming back from 219.80.240.93
		// but if we are pinging ping -n 20 -w 5000 -l 64 219.80.240.93  we have 0% loss
		// A resolution would be:
		// - as soon as we get a hop, we start pinging directly that hop, with a greater TTL
		// - a drawback would be that, some servers are configured to reply for TTL transit expire, but not to ping requests, so,
		// for these servers we'll have 100% loss
		DWORD dwReplyCount = wmtrnet->lpfnIcmpSendEcho2(wmtrnet->hICMP, 0,NULL,NULL, current->address, achReqData, nDataLen, lpstIPInfo, achRepData, sizeof(achRepData), wmtrnet->wmtrdlg->timeoutMs);
		wmtrnet->AddXmit(current->ttl - 1);
		if(dwReplyCount) {
			TRACE_MSG("TTL " << (int)current->ttl << " reply TTL " << (int)icmp_echo_reply.Options.Ttl << " Status " << icmp_echo_reply.Status << " Reply count " << dwReplyCount);
			switch(icmp_echo_reply.Status) {
			case IP_SUCCESS:
			case IP_TTL_EXPIRED_TRANSIT:
				wmtrnet->UpdateRTT(current->ttl - 1, icmp_echo_reply.RoundTripTime);
				wmtrnet->AddReturned(current->ttl - 1);
				wmtrnet->SetAddr(current->ttl - 1, icmp_echo_reply.Address);
				break;
			default:
				wmtrnet->SetErrorName(current->ttl - 1, icmp_echo_reply.Status);
			}
			if((DWORD)(wmtrnet->wmtrdlg->interval * 1000) > icmp_echo_reply.RoundTripTime)
				Sleep((DWORD)(wmtrnet->wmtrdlg->interval * 1000) - icmp_echo_reply.RoundTripTime);
		} else {
			DWORD err=GetLastError();
			wmtrnet->SetErrorName(current->ttl - 1, err);
			switch(err) {
			case IP_REQ_TIMED_OUT: break;
			default:
				Sleep((DWORD)(wmtrnet->wmtrdlg->interval * 1000));
			}
		}
	}//end loop
	TRACE_MSG("Thread with TTL=" << (int)current->ttl << " stopped.");
	delete p;
	return 0;
}

unsigned WINAPI TraceThread6(void* p)
{
	static sockaddr_in6 sockaddrfrom= {AF_INET6,0,0,in6addr_any,0};
	trace_thread6* current = (trace_thread6*)p;
	WinMTRNet* wmtrnet = current->winmtr;
	TRACE_MSG("Thread with TTL=" << (int)current->ttl << " started.");
	
	IPINFO			stIPInfo, *lpstIPInfo;
	char			achReqData[8192];
	WORD			nDataLen = wmtrnet->wmtrdlg->pingsize;
	union {
		ICMPV6_ECHO_REPLY icmpv6_echo_reply;
		char achRepData[sizeof(PICMPV6_ECHO_REPLY) + 8192];
	};
	
	lpstIPInfo				= &stIPInfo;
	stIPInfo.Ttl			= (UCHAR)current->ttl;
	stIPInfo.Tos			= (wmtrnet->wmtrdlg->tos >= 0) ? (UCHAR)wmtrnet->wmtrdlg->tos : 0;
	stIPInfo.Flags			= IPFLAG_DONT_FRAGMENT;
	stIPInfo.OptionsSize	= 0;
	stIPInfo.OptionsData	= NULL;
	for(int i=0; i<nDataLen; ++i) achReqData[i]=32;//whitespaces
	if(wmtrnet->wmtrdlg->bitPattern >= 0) {
		int pattern = wmtrnet->wmtrdlg->bitPattern;
		if(pattern > 255) pattern = rand() % 256;
		memset(achReqData, pattern, nDataLen);
	}
	while(wmtrnet->tracing) {
		while(wmtrnet->wmtrdlg->paused && wmtrnet->tracing) {
			Sleep(100);
		}
		if(current->ttl > wmtrnet->GetMax()) break;
		DWORD dwReplyCount = wmtrnet->lpfnIcmp6SendEcho2(wmtrnet->hICMP6, 0,NULL,NULL, &sockaddrfrom, &current->address, achReqData, nDataLen, lpstIPInfo, achRepData, sizeof(achRepData), wmtrnet->wmtrdlg->timeoutMs);
		wmtrnet->AddXmit(current->ttl - 1);
		if(dwReplyCount) {
			TRACE_MSG("TTL " << (int)current->ttl << " Status " << icmpv6_echo_reply.Status << " Reply count " << dwReplyCount);
			switch(icmpv6_echo_reply.Status) {
			case IP_SUCCESS:
			case IP_TTL_EXPIRED_TRANSIT:
				wmtrnet->UpdateRTT(current->ttl - 1, icmpv6_echo_reply.RoundTripTime);
				wmtrnet->AddReturned(current->ttl - 1);
				wmtrnet->SetAddr6(current->ttl - 1, icmpv6_echo_reply.Address);
				break;
			default:
				wmtrnet->SetErrorName(current->ttl - 1, icmpv6_echo_reply.Status);
			}
			if((DWORD)(wmtrnet->wmtrdlg->interval * 1000) > icmpv6_echo_reply.RoundTripTime)
				Sleep((DWORD)(wmtrnet->wmtrdlg->interval * 1000) - icmpv6_echo_reply.RoundTripTime);
		} else {
			DWORD err=GetLastError();
			wmtrnet->SetErrorName(current->ttl - 1, err);
			switch(err) {
			case IP_REQ_TIMED_OUT: break;
			default:
				Sleep((DWORD)(wmtrnet->wmtrdlg->interval * 1000));
			}
		}
	}//end loop
	TRACE_MSG("Thread with TTL=" << (int)current->ttl << " stopped.");
	delete p;
	return 0;
}

sockaddr* WinMTRNet::GetAddr(int at)
{
	return (sockaddr*)&host[at].addr;
}

int WinMTRNet::GetName(int at, char* n)
{
	WaitForSingleObject(ghMutex, INFINITE);
	strcpy(n, host[at].name);
	ReleaseMutex(ghMutex);
	return 0;
}

int WinMTRNet::GetBest(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].best;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetWorst(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].worst;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetAvg(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].returned == 0 ? 0 : host[at].total / host[at].returned;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetStDev(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	double ret = 0.0;
	if(host[at].returned > 1) {
		ret = sqrt(host[at].rttM2 / (host[at].returned - 1));
	}
	ReleaseMutex(ghMutex);
	return static_cast<int>(ret);
}

int WinMTRNet::GetJitter(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].jitterCurrent;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetDrop(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].xmit - host[at].returned;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetGmean(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	double ret = 0.0;
	if(host[at].rttLogSamples > 0) {
		ret = exp(host[at].rttLogSum / host[at].rttLogSamples);
	}
	ReleaseMutex(ghMutex);
	return static_cast<int>(ret);
}

int WinMTRNet::GetJitterAvg(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = static_cast<int>(host[at].jitterMean);
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetJitterMax(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].jitterMax;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetJitterInt(int at)
{
	return GetJitterAvg(at);
}

const char* WinMTRNet::GetASN(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	const char* ret = host[at].asnValid ? host[at].asn : "";
	ReleaseMutex(ghMutex);
	return ret;
}

const char* WinMTRNet::GetOrg(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	const char* ret = host[at].asnValid ? host[at].org : "";
	ReleaseMutex(ghMutex);
	return ret;
}

const char* WinMTRNet::GetPrefix(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	const char* ret = host[at].asnValid ? host[at].prefix : "";
	ReleaseMutex(ghMutex);
	return ret;
}

const char* WinMTRNet::GetCountry(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	const char* ret = host[at].asnValid ? host[at].country : "";
	ReleaseMutex(ghMutex);
	return ret;
}

const char* WinMTRNet::GetRegistry(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	const char* ret = host[at].asnValid ? host[at].registry : "";
	ReleaseMutex(ghMutex);
	return ret;
}

const char* WinMTRNet::GetAllocated(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	const char* ret = host[at].asnValid ? host[at].allocated : "";
	ReleaseMutex(ghMutex);
	return ret;
}
int WinMTRNet::GetPercent(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = (host[at].xmit == 0) ? 0 : (100 - (100 * host[at].returned / host[at].xmit));
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetLast(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].last;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetReturned(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].returned;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetXmit(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].xmit;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetMax()
{
	// @todo : improve this (last hop guess)
	WaitForSingleObject(ghMutex, INFINITE);
	int max=0;//first try to find target, if not found, find best guess (doesn't work actually :P)
	if(host[0].addr6.sin6_family==AF_INET6) {
		for(; max<MAX_HOPS && memcmp(&host[max++].addr6.sin6_addr,&last_remote_addr6,sizeof(in6_addr)););
		if(max==MAX_HOPS) {
			while(max>1 && !memcmp(&host[max-1].addr6.sin6_addr,&host[max-2].addr6.sin6_addr,sizeof(in6_addr)) && (host[max-1].addr6.sin6_addr.u.Word[0]|host[max-1].addr6.sin6_addr.u.Word[1]|host[max-1].addr6.sin6_addr.u.Word[2]|host[max-1].addr6.sin6_addr.u.Word[3]|host[max-1].addr6.sin6_addr.u.Word[4]|host[max-1].addr6.sin6_addr.u.Word[5]|host[max-1].addr6.sin6_addr.u.Word[6]|host[max-1].addr6.sin6_addr.u.Word[7])) --max;
		}
	} else {
		for(; max<MAX_HOPS && host[max++].addr.sin_addr.s_addr!=last_remote_addr.s_addr;);
		if(max==MAX_HOPS) {
			while(max>1 && host[max-1].addr.sin_addr.s_addr==host[max-2].addr.sin_addr.s_addr && host[max-1].addr.sin_addr.s_addr) --max;
		}
	}
	ReleaseMutex(ghMutex);
	if(max > wmtrdlg->maxHops && wmtrdlg->maxHops > 0) max = wmtrdlg->maxHops;
	return max;
}

void WinMTRNet::SetAddr(int at, u_long addr)
{
	WaitForSingleObject(ghMutex, INFINITE);
	if(host[at].addr.sin_addr.s_addr==0) {
		TRACE_MSG("Start DnsResolverThread for new address " << addr << ". Old addr value was " << host[at].addr.sin_addr.s_addr);
		host[at].addr.sin_family=AF_INET;
		host[at].addr.sin_addr.s_addr=addr;
		dns_resolver_thread* dnt=new dns_resolver_thread;
		dnt->index=at;
		dnt->winmtr=this;
		if(wmtrdlg->useDNS) _beginthread(DnsResolverThread, 0, dnt);
		else DnsResolverThread(dnt);
		if(wmtrdlg->asnEnabled) {
			mtr::IPv4Address ip(ntohl(addr));
			auto info = asnResolver.resolve(mtr::NetworkAddress{ip});
			if(info) {
				host[at].asnValid = true;
				CopyToBuffer(host[at].asn, sizeof(host[at].asn), "AS" + std::to_string(info->number));
				CopyToBuffer(host[at].org, sizeof(host[at].org), info->organization);
				CopyToBuffer(host[at].prefix, sizeof(host[at].prefix), info->prefix);
				CopyToBuffer(host[at].country, sizeof(host[at].country), info->country);
				CopyToBuffer(host[at].registry, sizeof(host[at].registry), info->registry);
				CopyToBuffer(host[at].allocated, sizeof(host[at].allocated), info->allocated);
			} else {
				host[at].asnValid = false;
			}
		}
	}
	ReleaseMutex(ghMutex);
}

void WinMTRNet::SetAddr6(int at, IPV6_ADDRESS_EX addrex)
{
	WaitForSingleObject(ghMutex, INFINITE);
	if(!(host[at].addr6.sin6_addr.u.Word[0]|host[at].addr6.sin6_addr.u.Word[1]|host[at].addr6.sin6_addr.u.Word[2]|host[at].addr6.sin6_addr.u.Word[3]|host[at].addr6.sin6_addr.u.Word[4]|host[at].addr6.sin6_addr.u.Word[5]|host[at].addr6.sin6_addr.u.Word[6]|host[at].addr6.sin6_addr.u.Word[7])) {
		TRACE_MSG("Start DnsResolverThread for new address " << addrex.sin6_addr[0] << ". Old addr value was " << host[at].addr6.sin6_addr.u.Word[0]);
		host[at].addr6.sin6_family=AF_INET6;
		host[at].addr6.sin6_addr=*(in6_addr*)&addrex.sin6_addr;
		dns_resolver_thread* dnt=new dns_resolver_thread;
		dnt->index=at;
		dnt->winmtr=this;
		if(wmtrdlg->useDNS) _beginthread(DnsResolverThread,0,dnt);
		else DnsResolverThread(dnt);
		if(wmtrdlg->asnEnabled) {
			std::array<uint8_t, 16> bytes{};
			std::memcpy(bytes.data(), addrex.sin6_addr, 16);
			mtr::IPv6Address ip(bytes);
			auto info = asnResolver.resolve(mtr::NetworkAddress{ip});
			if(info) {
				host[at].asnValid = true;
				CopyToBuffer(host[at].asn, sizeof(host[at].asn), "AS" + std::to_string(info->number));
				CopyToBuffer(host[at].org, sizeof(host[at].org), info->organization);
				CopyToBuffer(host[at].prefix, sizeof(host[at].prefix), info->prefix);
				CopyToBuffer(host[at].country, sizeof(host[at].country), info->country);
				CopyToBuffer(host[at].registry, sizeof(host[at].registry), info->registry);
				CopyToBuffer(host[at].allocated, sizeof(host[at].allocated), info->allocated);
			} else {
				host[at].asnValid = false;
			}
		}
	}
	ReleaseMutex(ghMutex);
}

void WinMTRNet::SetName(int at, char* n)
{
	WaitForSingleObject(ghMutex, INFINITE);
	strcpy(host[at].name, n);
	ReleaseMutex(ghMutex);
}

void WinMTRNet::SetErrorName(int at, DWORD errnum)
{
	const char* name;
	switch(errnum) {
	case IP_BUF_TOO_SMALL:
		name="Reply buffer too small."; break;
	case IP_DEST_NET_UNREACHABLE:
		name="Destination network unreachable."; break;
	case IP_DEST_HOST_UNREACHABLE:
		name="Destination host unreachable."; break;
	case IP_DEST_PROT_UNREACHABLE:
		name="Destination protocol unreachable."; break;
	case IP_DEST_PORT_UNREACHABLE:
		name="Destination port unreachable."; break;
	case IP_NO_RESOURCES:
		name="Insufficient IP resources were available."; break;
	case IP_BAD_OPTION:
		name="Bad IP option was specified."; break;
	case IP_HW_ERROR:
		name="Hardware error occurred."; break;
	case IP_PACKET_TOO_BIG:
		name="Packet was too big."; break;
	case IP_REQ_TIMED_OUT:
		name="Request timed out."; break;
	case IP_BAD_REQ:
		name="Bad request."; break;
	case IP_BAD_ROUTE:
		name="Bad route."; break;
	case IP_TTL_EXPIRED_REASSEM:
		name="The time to live expired during fragment reassembly."; break;
	case IP_PARAM_PROBLEM:
		name="Parameter problem."; break;
	case IP_SOURCE_QUENCH:
		name="Datagrams are arriving too fast to be processed and datagrams may have been discarded."; break;
	case IP_OPTION_TOO_BIG:
		name="An IP option was too big."; break;
	case IP_BAD_DESTINATION:
		name="Bad destination."; break;
	case IP_GENERAL_FAILURE:
		name="General failure."; break;
	default:
		TRACE_MSG("==UNKNOWN ERROR== " << errnum);
		name="Unknown error! (please report)"; break;
	}
	WaitForSingleObject(ghMutex, INFINITE);
	if(!*host[at].name)
		strcpy(host[at].name,name);
	ReleaseMutex(ghMutex);
}

void WinMTRNet::UpdateRTT(int at, int rtt)
{
	WaitForSingleObject(ghMutex, INFINITE);
	host[at].last=rtt;
	host[at].total+=rtt;
	if(host[at].best>rtt || host[at].xmit==1)
		host[at].best=rtt;
	if(host[at].worst<rtt)
		host[at].worst=rtt;
	if(!host[at].hasPrev) {
		host[at].hasPrev = true;
	} else {
		host[at].jitterCurrent = abs(rtt - host[at].prev);
		host[at].jitterSamples += 1;
		host[at].jitterMean += (host[at].jitterCurrent - host[at].jitterMean) / host[at].jitterSamples;
		if(host[at].jitterCurrent > host[at].jitterMax) host[at].jitterMax = host[at].jitterCurrent;
	}
	host[at].prev = rtt;
	int count = host[at].returned + 1;
	double delta = rtt - host[at].rttMean;
	host[at].rttMean += delta / count;
	double delta2 = rtt - host[at].rttMean;
	host[at].rttM2 += delta * delta2;
	if(rtt > 0) {
		host[at].rttLogSum += log(static_cast<double>(rtt));
		host[at].rttLogSamples += 1;
	}
	ReleaseMutex(ghMutex);
}

void WinMTRNet::AddReturned(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	++host[at].returned;
	ReleaseMutex(ghMutex);
}

void WinMTRNet::AddXmit(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	++host[at].xmit;
	ReleaseMutex(ghMutex);
}

void DnsResolverThread(void* p)
{
	dns_resolver_thread* dnt=(dns_resolver_thread*)p;
	WinMTRNet* wn=dnt->winmtr;
	char hostname[NI_MAXHOST];
	if(!getnameinfo(wn->GetAddr(dnt->index),sizeof(sockaddr_in6),hostname,NI_MAXHOST,NULL,0,NI_NUMERICHOST)) {
		wn->SetName(dnt->index,hostname);
	}
	if(wn->wmtrdlg->useDNS) {
		TRACE_MSG("DNS resolver thread started.");
		if(!getnameinfo(wn->GetAddr(dnt->index),sizeof(sockaddr_in6),hostname,NI_MAXHOST,NULL,0,0)) {
			wn->SetName(dnt->index,hostname);
		}
		TRACE_MSG("DNS resolver thread stopped.");
	}
	delete p;
}
