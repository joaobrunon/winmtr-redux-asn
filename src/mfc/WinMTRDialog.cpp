//*****************************************************************************
// FILE:            WinMTRDialog.cpp
//
//
//*****************************************************************************

#include "WinMTRGlobal.h"
#include "WinMTRDialog.h"
#include "WinMTROptions.h"
#include "WinMTRProperties.h"
#include "WinMTRNet.h"
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <mutex>
#include <iphlpapi.h>
#include <winhttp.h>

#ifndef NOMINMAX
#define NOMINMAX
#endif

#define WM_APP_UPDATE_IPINFO (WM_APP + 1)

static const char* IpinfoLabel(int mode);
static const char* OrderLabel(char code);

#ifdef _DEBUG
#	define TRACE_MSG(msg)									\
	{														\
	std::ostringstream dbg_msg(std::ostringstream::out);	\
	dbg_msg << msg << std::endl;							\
	OutputDebugString(dbg_msg.str().c_str());				\
	}
#	define new DEBUG_NEW
#	undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#else
#	define TRACE_MSG(msg)
#endif

void PingThread(void* p);
static unsigned WINAPI WanInfoThread(void* p);

static std::string EscapeJsonString(const char* input)
{
	std::string out;
	if(!input) return out;
	for(const unsigned char ch : std::string(input)) {
		switch(ch) {
			case '\\': out += "\\\\"; break;
			case '\"': out += "\\\""; break;
			case '\b': out += "\\b"; break;
			case '\f': out += "\\f"; break;
			case '\n': out += "\\n"; break;
			case '\r': out += "\\r"; break;
			case '\t': out += "\\t"; break;
			default:
				if(ch < 0x20) {
					char buf[7];
					sprintf(buf, "\\u%04x", ch);
					out += buf;
				} else {
					out.push_back(static_cast<char>(ch));
				}
				break;
		}
	}
	return out;
}

static std::string EscapeCsvField(const char* input)
{
	if(!input) return "";
	std::string field(input);
	bool needs_quotes = field.find_first_of(",\"\r\n") != std::string::npos;
	if(!needs_quotes) return field;

	std::string out;
	out.reserve(field.size() + 2);
	out.push_back('\"');
	for(char ch : field) {
		if(ch == '\"') out.push_back('\"');
		out.push_back(ch);
	}
	out.push_back('\"');
	return out;
}

static const char* IpinfoLabel(int mode)
{
	switch(mode) {
	case 0: return "ASN";
	case 1: return "Prefix";
	case 2: return "Country";
	case 3: return "Registry";
	case 4: return "Allocated";
	default: return "ASN";
	}
}

static const char* OrderLabel(char code)
{
	switch(code) {
	case 'L': return "Loss %";
	case 'D': return "Drop";
	case 'R': return "Recv";
	case 'S': return "Sent";
	case 'N': return "Last";
	case 'B': return "Best";
	case 'A': return "Avg";
	case 'W': return "Wrst";
	case 'V': return "StDev";
	case 'G': return "Gmean";
	case 'J': return "Jttr";
	case 'M': return "Javg";
	case 'X': return "Jmax";
	case 'I': return "Jint";
	default: return "";
	}
}

static std::string ExtractJsonString(const std::string& json, const char* key)
{
	std::string needle = "\"";
	needle += key;
	needle += "\"";
	size_t pos = json.find(needle);
	if(pos == std::string::npos) return "";
	pos = json.find(':', pos + needle.size());
	if(pos == std::string::npos) return "";
	++pos;
	while(pos < json.size() && isspace(static_cast<unsigned char>(json[pos]))) {
		++pos;
	}
	if(pos >= json.size() || json[pos] != '\"') return "";
	++pos;
	std::string value;
	while(pos < json.size()) {
		char ch = json[pos++];
		if(ch == '\\\\') {
			if(pos < json.size()) {
				value.push_back(json[pos++]);
			}
			continue;
		}
		if(ch == '\"') break;
		value.push_back(ch);
	}
	return value;
}

static std::string ExtractAsnFromOrg(const std::string& org)
{
	size_t pos = org.find("AS");
	if(pos == std::string::npos) return "";
	size_t start = pos;
	pos += 2;
	while(pos < org.size() && isdigit(static_cast<unsigned char>(org[pos]))) {
		++pos;
	}
	if(pos == start + 2) return "";
	return org.substr(start, pos - start);
}

static bool HttpGet(const wchar_t* host, const wchar_t* path, std::string& out)
{
	out.clear();
	HINTERNET session = WinHttpOpen(L"WinMTR/1.0",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS,
		0);
	if(!session) return false;

	WinHttpSetTimeouts(session, 3000, 3000, 3000, 3000);

	HINTERNET connect = WinHttpConnect(session, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
	if(!connect) {
		WinHttpCloseHandle(session);
		return false;
	}

	HINTERNET request = WinHttpOpenRequest(connect, L"GET", path,
		NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
		WINHTTP_FLAG_SECURE);
	if(!request) {
		WinHttpCloseHandle(connect);
		WinHttpCloseHandle(session);
		return false;
	}

	BOOL sent = WinHttpSendRequest(request,
		WINHTTP_NO_ADDITIONAL_HEADERS, 0,
		WINHTTP_NO_REQUEST_DATA, 0,
		0, 0);
	if(sent) {
		sent = WinHttpReceiveResponse(request, NULL);
	}
	if(!sent) {
		WinHttpCloseHandle(request);
		WinHttpCloseHandle(connect);
		WinHttpCloseHandle(session);
		return false;
	}

	DWORD size = 0;
	do {
		if(!WinHttpQueryDataAvailable(request, &size)) break;
		if(size == 0) break;
		std::string buffer;
		buffer.resize(size);
		DWORD read = 0;
		if(!WinHttpReadData(request, &buffer[0], size, &read)) break;
		out.append(buffer.data(), read);
	} while(size > 0);

	WinHttpCloseHandle(request);
	WinHttpCloseHandle(connect);
	WinHttpCloseHandle(session);

	return !out.empty();
}

static bool TryFetchWanInfo(const wchar_t* host, const wchar_t* path, std::string& ip, std::string& asn, std::string& org)
{
	std::string json;
	if(!HttpGet(host, path, json)) return false;

	ip = ExtractJsonString(json, "ip");
	asn = ExtractJsonString(json, "asn");
	org = ExtractJsonString(json, "org");
	if(asn.empty() && !org.empty()) {
		asn = ExtractAsnFromOrg(org);
	}
	return !ip.empty();
}

//*****************************************************************************
// BEGIN_MESSAGE_MAP
//
//
//*****************************************************************************
BEGIN_MESSAGE_MAP(WinMTRDialog, CDialog)
	ON_WM_PAINT()
	ON_WM_SIZE()
	ON_WM_SIZING()
	ON_WM_QUERYDRAGICON()
	ON_WM_CTLCOLOR()
	ON_BN_CLICKED(ID_RESTART, OnRestart)
	ON_BN_CLICKED(ID_OPTIONS, OnOptions)
	ON_BN_CLICKED(IDC_CHECK_SHOWIPS, OnToggleShowIps)
	ON_BN_CLICKED(ID_CTTC, OnCTTC)
	ON_BN_CLICKED(ID_CHTC, OnCHTC)
	ON_BN_CLICKED(ID_EXPT, OnEXPT)
	ON_BN_CLICKED(ID_EXPH, OnEXPH)
	ON_BN_CLICKED(ID_EXPCSV, OnEXPCSV)
	ON_BN_CLICKED(ID_EXPJSON, OnEXPJSON)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST_MTR, OnDblclkList)
	ON_NOTIFY(TCN_SELCHANGE, IDC_TAB_VIEW, &WinMTRDialog::OnTabSelchange)
	ON_CBN_SELCHANGE(IDC_COMBO_HOST, &WinMTRDialog::OnCbnSelchangeComboHost)
	ON_CBN_SELENDOK(IDC_COMBO_HOST, &WinMTRDialog::OnCbnSelendokComboHost)
	ON_CBN_CLOSEUP(IDC_COMBO_HOST, &WinMTRDialog::OnCbnCloseupComboHost)
	ON_WM_TIMER()
	ON_WM_CLOSE()
	ON_BN_CLICKED(IDCANCEL, &WinMTRDialog::OnBnClickedCancel)
	ON_MESSAGE(WM_APP_UPDATE_IPINFO, &WinMTRDialog::OnUpdateIpInfo)
END_MESSAGE_MAP()


//*****************************************************************************
// WinMTRDialog::WinMTRDialog
//
//
//*****************************************************************************
WinMTRDialog::WinMTRDialog(CWnd* pParent)
	: CDialog(WinMTRDialog::IDD, pParent),
	  state(IDLE),
	  transition(IDLE_TO_IDLE)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_autostart = 0;
	useDNS = DEFAULT_DNS;
	interval = DEFAULT_INTERVAL;
	pingsize = DEFAULT_PING_SIZE;
	maxLRU = DEFAULT_MAX_LRU;
	maxHops = DEFAULT_MAX_HOPS;
	firstTtl = DEFAULT_FIRST_TTL;
	timeoutMs = DEFAULT_TIMEOUT_MS;
	tos = DEFAULT_TOS;
	bitPattern = DEFAULT_BITPATTERN;
	probeMode = 0;
	port = DEFAULT_PORT;
	localPort = DEFAULT_LOCALPORT;
	orderString = "LRS N BAWV";
	asnEnabled = true;
	ipinfoMode = 0;
	showIps = false;
	paused = false;
	m_autostart = 1;
	localIpv4 = "";
	localIpv6 = "";
	wanIpv4 = "";
	wanIpv6 = "";
	wanAsn = "";
	wanInfoThread = NULL;
	nrLRU = 0;
	strcpy(msz_defaulthostname, "8.8.8.8");
	m_autostart = 1;
	m_metricsCardColor = RGB(245, 247, 250);
	m_networkCardColor = RGB(236, 241, 247);
	m_statusTextColor = RGB(30, 30, 30);
	m_statusValueColor = RGB(30, 90, 150);
	
	hasIntervalFromCmdLine = false;
	hasPingsizeFromCmdLine = false;
	hasMaxLRUFromCmdLine = false;
	hasUseDNSFromCmdLine = false;
	hasUseIPv6FromCmdLine = false;
	
	traceThreadMutex = CreateMutex(NULL, FALSE, NULL);
	wmtrnet = new WinMTRNet(this);
	if(!wmtrnet->hasIPv6) m_checkIPv6.EnableWindow(FALSE);
	useIPv6=2;
}

WinMTRDialog::~WinMTRDialog()
{
	delete wmtrnet;
	CloseHandle(traceThreadMutex);
}

//*****************************************************************************
// WinMTRDialog::DoDataExchange
//
//
//*****************************************************************************
void WinMTRDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, ID_OPTIONS, m_buttonOptions);
	DDX_Control(pDX, IDCANCEL, m_buttonExit);
	DDX_Control(pDX, ID_RESTART, m_buttonStart);
	DDX_Control(pDX, IDC_COMBO_HOST, m_comboHost);
	DDX_Control(pDX, IDC_CHECK_IPV6, m_checkIPv6);
	DDX_Control(pDX, IDC_CHECK_SHOWIPS, m_checkShowIps);
	DDX_Control(pDX, IDC_LIST_MTR, m_listMTR);
	DDX_Control(pDX, IDC_TAB_VIEW, m_tabView);
	DDX_Control(pDX, IDC_STATICS, m_staticS);
	DDX_Control(pDX, IDC_STATICJ, m_staticJ);
	DDX_Control(pDX, ID_EXPH, m_buttonExpH);
	DDX_Control(pDX, ID_EXPT, m_buttonExpT);
	DDX_Control(pDX, ID_EXPCSV, m_buttonExpCsv);
	DDX_Control(pDX, ID_EXPJSON, m_buttonExpJson);
}


//*****************************************************************************
// WinMTRDialog::OnInitDialog
//
//
//*****************************************************************************
BOOL WinMTRDialog::OnInitDialog()
{
	CDialog::OnInitDialog();
	if(!wmtrnet->initialized) {
		EndDialog(-1);
		return TRUE;
	}
	
#ifndef  _WIN64
	char caption[] = {"WinMTR (Redux) v1.00 32bit"};
#else
	char caption[] = {"WinMTR (Redux) v1.00 64bit"};
#endif
	
	SetTimer(1, WINMTR_DIALOG_TIMER, NULL);
	SetWindowText(caption);
	
	SetIcon(m_hIcon, TRUE);
	SetIcon(m_hIcon, FALSE);
	
	if(!statusBar.Create(this))
		AfxMessageBox("Error creating status bar");
	statusBar.GetStatusBarCtrl().SetMinHeight(23);
	
	UINT sbi[1];
	sbi[0] = IDS_STRING_SB_NAME;
	statusBar.SetIndicators(sbi,1);
	
	// create Appnor button
	if(m_buttonAppnor.Create(_T("www.appnor.com"), WS_CHILD|WS_VISIBLE|WS_TABSTOP, CRect(0,0,0,0), &statusBar, 1234)) {
		m_buttonAppnor.SetURL("http://appnor.com/?utm_source=winmtr&utm_medium=desktop&utm_campaign=software");
		if(statusBar.AddPane(1234,1)) {
			statusBar.SetPaneWidth(statusBar.CommandToIndex(1234),100);
			statusBar.AddPaneControl(m_buttonAppnor,1234,true);
		}
	}

	int statusIndex = statusBar.CommandToIndex(IDS_STRING_SB_NAME);
	if(statusIndex >= 0) {
		statusBar.SetPaneInfo(statusIndex, IDS_STRING_SB_NAME, SBPS_STRETCH, 0);
	}

	m_tabView.InsertItem(0, "MTR");
	m_tabView.InsertItem(1, "Status");
	m_tabView.SetCurSel(0);
	ShowTab(0);
	m_metricsCardBrush.DeleteObject();
	m_networkCardBrush.DeleteObject();
	m_metricsCardBrush.CreateSolidBrush(m_metricsCardColor);
	m_networkCardBrush.CreateSolidBrush(m_networkCardColor);
	ApplyStatusFonts();

	RefreshLocalIpInfo();
	UpdateStatusTab();
	StartWanInfoRefresh();
	
	m_comboHost.SetFocus();
	
	// We need to resize the dialog to make room for control bars.
	// First, figure out how big the control bars are.
	CRect rcClientStart;
	CRect rcClientNow;
	GetClientRect(rcClientStart);
	RepositionBars(AFX_IDW_CONTROLBAR_FIRST, AFX_IDW_CONTROLBAR_LAST,
				   0, reposQuery, rcClientNow);
				   
	// Now move all the controls so they are in the same relative
	// position within the remaining client area as they would be
	// with no control bars.
	CPoint ptOffset(rcClientNow.left - rcClientStart.left,
					rcClientNow.top - rcClientStart.top);
					
	CRect  rcChild;
	CWnd* pwndChild = GetWindow(GW_CHILD);
	while(pwndChild) {
		pwndChild->GetWindowRect(rcChild);
		ScreenToClient(rcChild);
		rcChild.OffsetRect(ptOffset);
		pwndChild->MoveWindow(rcChild, FALSE);
		pwndChild = pwndChild->GetNextWindow();
	}
	
	// Adjust the dialog window dimensions
	CRect rcWindow;
	GetWindowRect(rcWindow);
	rcWindow.right += rcClientStart.Width() - rcClientNow.Width();
	rcWindow.bottom += rcClientStart.Height() - rcClientNow.Height();
	MoveWindow(rcWindow, FALSE);
	
	// And position the control bars
	RepositionBars(AFX_IDW_CONTROLBAR_FIRST, AFX_IDW_CONTROLBAR_LAST, 0);
	
	InitRegistry();
	ApplyColumnOrder();
	
	if(m_autostart) {
		CString host;
		m_comboHost.GetWindowText(host);
		if(host.IsEmpty()) {
			if(msz_defaulthostname[0] != '\0') {
				m_comboHost.SetWindowText(msz_defaulthostname);
			} else if(m_comboHost.GetCount() > 0) {
				CString first;
				m_comboHost.GetLBText(0, first);
				if(first.CompareNoCase(CString((LPCSTR)IDS_STRING_CLEAR_HISTORY)) != 0) {
					m_comboHost.SetWindowText(first);
				}
			}
		}
		m_comboHost.GetWindowText(host);
		if(!host.IsEmpty()) {
			OnRestart();
		}
	}
	
	return FALSE;
}

std::vector<char> WinMTRDialog::ParseOrderFields(const std::string& order) const
{
	std::vector<char> fields;
	for(char ch : order) {
		if(isspace(static_cast<unsigned char>(ch))) continue;
		char up = static_cast<char>(toupper(static_cast<unsigned char>(ch)));
		switch(up) {
		case 'L': case 'D': case 'R': case 'S':
		case 'N': case 'B': case 'A': case 'W':
		case 'V': case 'G': case 'J': case 'M':
		case 'X': case 'I':
			fields.push_back(up);
			break;
		default:
			break;
		}
	}
	if(fields.empty()) {
		fields.push_back('L');
		fields.push_back('R');
		fields.push_back('S');
		fields.push_back('N');
		fields.push_back('B');
		fields.push_back('A');
		fields.push_back('W');
		fields.push_back('V');
	}
	return fields;
}

void WinMTRDialog::ApplyColumnOrder()
{
	orderFields = ParseOrderFields(orderString);
	while(m_listMTR.DeleteColumn(0)) {}
	m_listMTR.DeleteAllItems();

	m_listMTR.InsertColumn(0, "Host", LVCFMT_LEFT, 220, -1);
	m_listMTR.InsertColumn(1, "Nr", LVCFMT_LEFT, 30, -1);

	auto addColumn = [&](const char* name, int width) {
		int index = m_listMTR.GetHeaderCtrl()->GetItemCount();
		m_listMTR.InsertColumn(index, name, LVCFMT_RIGHT, width, -1);
	};

	for(char code : orderFields) {
		switch(code) {
		case 'L': addColumn("Loss %", 50); break;
		case 'D': addColumn("Drop", 50); break;
		case 'R': addColumn("Recv", 50); break;
		case 'S': addColumn("Sent", 50); break;
		case 'N': addColumn("Last", 50); break;
		case 'B': addColumn("Best", 50); break;
		case 'A': addColumn("Avg", 50); break;
		case 'W': addColumn("Wrst", 50); break;
		case 'V': addColumn("StDev", 50); break;
		case 'G': addColumn("Gmean", 50); break;
		case 'J': addColumn("Jttr", 50); break;
		case 'M': addColumn("Javg", 50); break;
		case 'X': addColumn("Jmax", 50); break;
		case 'I': addColumn("Jint", 50); break;
		default: break;
		}
	}
	if(asnEnabled) {
		addColumn(IpinfoLabel(ipinfoMode), 120);
	}
}

CString WinMTRDialog::FormatFieldValue(char code, int index) const
{
	char buf[32];
	switch(code) {
	case 'L':
		sprintf(buf, "%d", wmtrnet->GetPercent(index));
		break;
	case 'D':
		sprintf(buf, "%d", wmtrnet->GetDrop(index));
		break;
	case 'R':
		sprintf(buf, "%d", wmtrnet->GetReturned(index));
		break;
	case 'S':
		sprintf(buf, "%d", wmtrnet->GetXmit(index));
		break;
	case 'N':
		sprintf(buf, "%d", wmtrnet->GetLast(index));
		break;
	case 'B':
		sprintf(buf, "%d", wmtrnet->GetBest(index));
		break;
	case 'A':
		sprintf(buf, "%d", wmtrnet->GetAvg(index));
		break;
	case 'W':
		sprintf(buf, "%d", wmtrnet->GetWorst(index));
		break;
	case 'V':
		sprintf(buf, "%d", wmtrnet->GetStDev(index));
		break;
	case 'G':
		sprintf(buf, "%d", wmtrnet->GetGmean(index));
		break;
	case 'J':
		sprintf(buf, "%d", wmtrnet->GetJitter(index));
		break;
	case 'M':
		sprintf(buf, "%d", wmtrnet->GetJitterAvg(index));
		break;
	case 'X':
		sprintf(buf, "%d", wmtrnet->GetJitterMax(index));
		break;
	case 'I':
		sprintf(buf, "%d", wmtrnet->GetJitterInt(index));
		break;
	default:
		buf[0] = '\0';
		break;
	}
	return CString(buf);
}

CString WinMTRDialog::FormatIpInfo(int index) const
{
	if(!asnEnabled) {
		return CString("-");
	}
	const char* asn = wmtrnet->GetASN(index);
	if(!asn || !*asn) {
		return (ipinfoMode == 0) ? CString("AS???") : CString("???");
	}
	switch(ipinfoMode) {
	case 0: {
		const char* org = wmtrnet->GetOrg(index);
		if(org && *org) {
			CString out;
			out.Format("%s %s", asn, org);
			return out;
		}
		return CString(asn);
	}
	case 1: return CString(wmtrnet->GetPrefix(index));
	case 2: return CString(wmtrnet->GetCountry(index));
	case 3: return CString(wmtrnet->GetRegistry(index));
	case 4: return CString(wmtrnet->GetAllocated(index));
	default: return CString(asn);
	}
}

CString WinMTRDialog::FormatHostLabel(int index) const
{
	char buf[255];
	wmtrnet->GetName(index, buf);
	if(!*buf) strcpy(buf, "No response from host");

	if(showIps) {
		char ipbuf[NI_MAXHOST];
		if(!getnameinfo(wmtrnet->GetAddr(index), sizeof(sockaddr_in6), ipbuf, NI_MAXHOST, NULL, 0, NI_NUMERICHOST)) {
			if(strcmp(buf, ipbuf) != 0 && strcmp(buf, "No response from host") != 0) {
				CString combined;
				combined.Format("%s (%s)", buf, ipbuf);
				return combined;
			}
			return CString(ipbuf);
		}
	}

	return CString(buf);
}

void WinMTRDialog::ShowTab(int index)
{
	const int statusControls[] = {
		IDC_STATUS_GROUP,
		IDC_STATUS_CARD_METRICS,
		IDC_STATUS_CARD_NETWORK,
		IDC_STATUS_RESP_LABEL,
		IDC_STATUS_LAG_ROUTER_LABEL,
		IDC_STATUS_LAG_INET_LABEL,
		IDC_STATUS_AVG_LABEL,
		IDC_STATUS_BEST_LABEL,
		IDC_STATUS_WORST_LABEL,
		IDC_STATUS_LATENCY_LABEL,
		IDC_STATUS_JITTER_LABEL,
		IDC_STATUS_LOSS_LABEL,
		IDC_STATUS_LAN_LABEL,
		IDC_STATUS_WAN_LABEL,
		IDC_STATUS_ASN_LABEL,
		IDC_STATUS_RESP_VALUE,
		IDC_STATUS_LAG_ROUTER_VALUE,
		IDC_STATUS_LAG_INET_VALUE,
		IDC_STATUS_AVG_VALUE,
		IDC_STATUS_BEST_VALUE,
		IDC_STATUS_WORST_VALUE,
		IDC_STATUS_LATENCY_VALUE,
		IDC_STATUS_JITTER_VALUE,
		IDC_STATUS_LOSS_VALUE,
		IDC_STATUS_LAN_VALUE,
		IDC_STATUS_WAN_VALUE,
		IDC_STATUS_ASN_VALUE
	};

	bool showStatus = (index == 1);
	m_listMTR.ShowWindow(showStatus ? SW_HIDE : SW_SHOW);
	for(int id : statusControls) {
		CWnd* ctrl = GetDlgItem(id);
		if(ctrl) ctrl->ShowWindow(showStatus ? SW_SHOW : SW_HIDE);
	}

	if(showStatus) {
		UpdateStatusTab();
	}
}

void WinMTRDialog::UpdateStatusTab()
{
	if(m_tabView.GetCurSel() != 1) return;

	int nh = wmtrnet->GetMax();
	int lastHop = -1;
	for(int i = nh - 1; i >= 0; --i) {
		if(wmtrnet->GetReturned(i) > 0) {
			lastHop = i;
			break;
		}
	}

	auto formatMs = [](int value, bool valid) -> CString {
		if(!valid) return "N/A";
		CString out;
		out.Format("%d ms", value);
		return out;
	};

	auto formatPct = [](int value) -> CString {
		if(value < 0) return "N/A";
		CString out;
		out.Format("%d%%", value);
		return out;
	};

	int routerHop = (nh > 0) ? 0 : -1;
	bool routerValid = (routerHop >= 0 && wmtrnet->GetReturned(routerHop) > 0);
	bool lastValid = (lastHop >= 0 && wmtrnet->GetReturned(lastHop) > 0);
	CString lagRouter = formatMs(routerValid ? wmtrnet->GetAvg(routerHop) : 0, routerValid);
	CString lagInternet = formatMs(lastValid ? wmtrnet->GetAvg(lastHop) : 0, lastValid);

	CString avg = formatMs(lastValid ? wmtrnet->GetAvg(lastHop) : 0, lastValid);
	CString best = formatMs(lastValid ? wmtrnet->GetBest(lastHop) : 0, lastValid);
	CString worst = formatMs(lastValid ? wmtrnet->GetWorst(lastHop) : 0, lastValid);
	CString latency = avg;
	CString jitter = formatMs(lastValid ? wmtrnet->GetJitterAvg(lastHop) : 0, lastValid);
	CString loss = lastValid ? formatPct(wmtrnet->GetPercent(lastHop)) : CString("N/A");
	CString resp = "N/A";
	if(lastValid) {
		int lossPct = wmtrnet->GetPercent(lastHop);
		if(lossPct >= 0) {
			int responsiveness = 100 - lossPct;
			resp = formatPct(responsiveness);
		}
	}

	CString lan;
	CString wan;
	CString asn;
	{
		std::lock_guard<std::mutex> lock(ipInfoMutex);
		if(!localIpv4.IsEmpty() || !localIpv6.IsEmpty()) {
			lan = localIpv4;
			if(!localIpv6.IsEmpty()) {
				if(!lan.IsEmpty()) lan += " / ";
				lan += localIpv6;
			}
		}
		if(!wanIpv4.IsEmpty() || !wanIpv6.IsEmpty()) {
			wan = wanIpv4;
			if(!wanIpv6.IsEmpty()) {
				if(!wan.IsEmpty()) wan += " / ";
				wan += wanIpv6;
			}
		}
		asn = wanAsn;
	}

	if(lan.IsEmpty()) lan = "N/A";
	if(wan.IsEmpty()) wan = "N/A";
	if(asn.IsEmpty()) asn = "N/A";

	SetDlgItemText(IDC_STATUS_RESP_VALUE, resp);
	SetDlgItemText(IDC_STATUS_LAG_ROUTER_VALUE, lagRouter);
	SetDlgItemText(IDC_STATUS_LAG_INET_VALUE, lagInternet);
	SetDlgItemText(IDC_STATUS_AVG_VALUE, avg);
	SetDlgItemText(IDC_STATUS_BEST_VALUE, best);
	SetDlgItemText(IDC_STATUS_WORST_VALUE, worst);
	SetDlgItemText(IDC_STATUS_LATENCY_VALUE, latency);
	SetDlgItemText(IDC_STATUS_JITTER_VALUE, jitter);
	SetDlgItemText(IDC_STATUS_LOSS_VALUE, loss);
	SetDlgItemText(IDC_STATUS_LAN_VALUE, lan);
	SetDlgItemText(IDC_STATUS_WAN_VALUE, wan);
	SetDlgItemText(IDC_STATUS_ASN_VALUE, asn);
}

void WinMTRDialog::ApplyStatusFonts()
{
	CFont* baseFont = GetFont();
	if(!baseFont) return;
	LOGFONT lf{};
	baseFont->GetLogFont(&lf);
	lf.lfWeight = FW_BOLD;
	m_statusValueFont.DeleteObject();
	if(!m_statusValueFont.CreateFontIndirect(&lf)) return;

	const int valueControls[] = {
		IDC_STATUS_RESP_VALUE,
		IDC_STATUS_LAG_ROUTER_VALUE,
		IDC_STATUS_LAG_INET_VALUE,
		IDC_STATUS_AVG_VALUE,
		IDC_STATUS_BEST_VALUE,
		IDC_STATUS_WORST_VALUE,
		IDC_STATUS_LATENCY_VALUE,
		IDC_STATUS_JITTER_VALUE,
		IDC_STATUS_LOSS_VALUE,
		IDC_STATUS_LAN_VALUE,
		IDC_STATUS_WAN_VALUE,
		IDC_STATUS_ASN_VALUE
	};

	for(int id : valueControls) {
		CWnd* ctrl = GetDlgItem(id);
		if(ctrl) ctrl->SetFont(&m_statusValueFont);
	}
}

void WinMTRDialog::RefreshLocalIpInfo()
{
	std::string v4;
	std::string v6;
	std::string v6LinkLocal;

	ULONG size = 0;
	DWORD flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
	DWORD res = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, NULL, &size);
	if(res != ERROR_BUFFER_OVERFLOW || size == 0) {
		return;
	}

	std::vector<unsigned char> buffer(size);
	IP_ADAPTER_ADDRESSES* addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
	if(GetAdaptersAddresses(AF_UNSPEC, flags, NULL, addrs, &size) != NO_ERROR) {
		return;
	}

	for(IP_ADAPTER_ADDRESSES* aa = addrs; aa; aa = aa->Next) {
		if(aa->OperStatus != IfOperStatusUp) continue;
		for(IP_ADAPTER_UNICAST_ADDRESS* ua = aa->FirstUnicastAddress; ua; ua = ua->Next) {
			if(!ua->Address.lpSockaddr) continue;
			if(ua->Address.lpSockaddr->sa_family == AF_INET) {
				sockaddr_in* sa = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
				ULONG addr = ntohl(sa->sin_addr.s_addr);
				if((addr >> 24) == 127) continue;
				if((addr >> 16) == 0xA9FE) continue;
				char buf[INET_ADDRSTRLEN] = {};
				if(inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf)) && v4.empty()) {
					v4 = buf;
				}
			} else if(ua->Address.lpSockaddr->sa_family == AF_INET6) {
				sockaddr_in6* sa6 = reinterpret_cast<sockaddr_in6*>(ua->Address.lpSockaddr);
				if(IN6_IS_ADDR_LOOPBACK(&sa6->sin6_addr)) continue;
				char buf[INET6_ADDRSTRLEN] = {};
				if(inet_ntop(AF_INET6, &sa6->sin6_addr, buf, sizeof(buf))) {
					if(IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr)) {
						if(v6LinkLocal.empty()) v6LinkLocal = buf;
					} else if(v6.empty()) {
						v6 = buf;
					}
				}
			}
		}
	}

	if(v6.empty()) v6 = v6LinkLocal;

	std::lock_guard<std::mutex> lock(ipInfoMutex);
	localIpv4 = v4.c_str();
	localIpv6 = v6.c_str();
}

void WinMTRDialog::UpdateIpInfoStatusBar()
{
	UpdateStatusTab();
}

void WinMTRDialog::SetStatusText(const CString& text)
{
	int paneIndex = statusBar.CommandToIndex(IDS_STRING_SB_NAME);
	if(paneIndex >= 0) {
		statusBar.SetPaneText(paneIndex, text);
	}
}

void WinMTRDialog::StartWanInfoRefresh()
{
	std::lock_guard<std::mutex> lock(ipInfoMutex);
	if(wanInfoThread) return;
	unsigned int tid = 0;
	wanInfoThread = reinterpret_cast<HANDLE>(_beginthreadex(NULL, 0, WanInfoThread, this, 0, &tid));
}

LRESULT WinMTRDialog::OnUpdateIpInfo(WPARAM, LPARAM)
{
	UpdateStatusTab();
	return 0;
}



//*****************************************************************************
// WinMTRDialog::InitRegistry
//
//
//*****************************************************************************
BOOL WinMTRDialog::InitRegistry()
{
	HKEY hKey, hKey_v;
	DWORD tmp_dword, value_size;
	LONG r;
	
	r = RegCreateKeyEx(HKEY_CURRENT_USER,"Software\\WinMTR",0,NULL,0,KEY_ALL_ACCESS,NULL,&hKey,NULL);
	if(r != ERROR_SUCCESS)
		return FALSE;
		
	RegSetValueEx(hKey,"Version", 0, REG_SZ, (const unsigned char*)WINMTR_VERSION, sizeof(WINMTR_VERSION)+1);
	RegSetValueEx(hKey,"License", 0, REG_SZ, (const unsigned char*)WINMTR_LICENSE, sizeof(WINMTR_LICENSE)+1);
	RegSetValueEx(hKey,"HomePage", 0, REG_SZ, (const unsigned char*)WINMTR_HOMEPAGE, sizeof(WINMTR_HOMEPAGE)+1);
	
	r = RegCreateKeyEx(hKey,"Config",0,NULL,0,KEY_ALL_ACCESS,NULL,&hKey_v,NULL);
	if(r != ERROR_SUCCESS)
		return FALSE;
		
	if(RegQueryValueEx(hKey_v, "PingSize", 0, NULL, (unsigned char*)&tmp_dword, &value_size) != ERROR_SUCCESS) {
		tmp_dword = pingsize;
		RegSetValueEx(hKey_v,"PingSize", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	} else {
		if(!hasPingsizeFromCmdLine) pingsize = (WORD)tmp_dword;
	}
	
	if(RegQueryValueEx(hKey_v, "MaxLRU", 0, NULL, (unsigned char*)&tmp_dword, &value_size) != ERROR_SUCCESS) {
		tmp_dword = maxLRU;
		RegSetValueEx(hKey_v,"MaxLRU", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	} else {
		if(!hasMaxLRUFromCmdLine) maxLRU = tmp_dword;
	}
	
	if(RegQueryValueEx(hKey_v, "UseDNS", 0, NULL, (unsigned char*)&tmp_dword, &value_size) != ERROR_SUCCESS) {
		tmp_dword = useDNS ? 1 : 0;
		RegSetValueEx(hKey_v,"UseDNS", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	} else {
		if(!hasUseDNSFromCmdLine) useDNS = (BOOL)tmp_dword;
	}
	if(RegQueryValueEx(hKey_v, "ShowIps", 0, NULL, (unsigned char*)&tmp_dword, &value_size) != ERROR_SUCCESS) {
		tmp_dword = showIps ? 1 : 0;
		RegSetValueEx(hKey_v,"ShowIps", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	} else {
		showIps = tmp_dword ? true : false;
	}
	if(RegQueryValueEx(hKey_v, "AsnEnabled", 0, NULL, (unsigned char*)&tmp_dword, &value_size) != ERROR_SUCCESS) {
		tmp_dword = asnEnabled ? 1 : 0;
		RegSetValueEx(hKey_v,"AsnEnabled", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	} else {
		asnEnabled = tmp_dword ? true : false;
	}
	if(RegQueryValueEx(hKey_v, "IpinfoMode", 0, NULL, (unsigned char*)&tmp_dword, &value_size) != ERROR_SUCCESS) {
		tmp_dword = ipinfoMode;
		RegSetValueEx(hKey_v,"IpinfoMode", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	} else {
		ipinfoMode = static_cast<int>(tmp_dword);
	}
	if(RegQueryValueEx(hKey_v, "UseIPv6", 0, NULL, (unsigned char*)&tmp_dword, &value_size) != ERROR_SUCCESS) {
		tmp_dword = useIPv6;
		RegSetValueEx(hKey_v,"UseIPv6", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	} else {
		if(!hasUseIPv6FromCmdLine) useIPv6 = (unsigned char)tmp_dword;
		if(useIPv6>2) useIPv6=1;
	}
	m_checkIPv6.SetCheck(useIPv6);
	m_checkShowIps.SetCheck(showIps ? BST_CHECKED : BST_UNCHECKED);
	
	if(RegQueryValueEx(hKey_v, "Interval", 0, NULL, (unsigned char*)&tmp_dword, &value_size) != ERROR_SUCCESS) {
		tmp_dword = (DWORD)(interval * 1000);
		RegSetValueEx(hKey_v,"Interval", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	} else {
		if(!hasIntervalFromCmdLine) interval = (float)tmp_dword / 1000.0;
	}

	if(RegQueryValueEx(hKey_v, "TimeoutMs", 0, NULL, (unsigned char*)&tmp_dword, &value_size) != ERROR_SUCCESS) {
		tmp_dword = timeoutMs;
		RegSetValueEx(hKey_v,"TimeoutMs", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	} else {
		timeoutMs = tmp_dword;
	}
	if(RegQueryValueEx(hKey_v, "MaxHops", 0, NULL, (unsigned char*)&tmp_dword, &value_size) != ERROR_SUCCESS) {
		tmp_dword = maxHops;
		RegSetValueEx(hKey_v,"MaxHops", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	} else {
		maxHops = tmp_dword;
	}
	if(RegQueryValueEx(hKey_v, "FirstTtl", 0, NULL, (unsigned char*)&tmp_dword, &value_size) != ERROR_SUCCESS) {
		tmp_dword = firstTtl;
		RegSetValueEx(hKey_v,"FirstTtl", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	} else {
		firstTtl = tmp_dword;
	}
	if(maxHops <= 0) maxHops = DEFAULT_MAX_HOPS;
	if(maxHops > MaxHost) maxHops = MaxHost;
	if(firstTtl <= 0) firstTtl = DEFAULT_FIRST_TTL;
	if(firstTtl > maxHops) firstTtl = maxHops;
	if(RegQueryValueEx(hKey_v, "Tos", 0, NULL, (unsigned char*)&tmp_dword, &value_size) != ERROR_SUCCESS) {
		tmp_dword = static_cast<DWORD>(tos);
		RegSetValueEx(hKey_v,"Tos", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	} else {
		tos = static_cast<int>(tmp_dword);
	}
	if(RegQueryValueEx(hKey_v, "BitPattern", 0, NULL, (unsigned char*)&tmp_dword, &value_size) != ERROR_SUCCESS) {
		tmp_dword = static_cast<DWORD>(bitPattern);
		RegSetValueEx(hKey_v,"BitPattern", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	} else {
		bitPattern = static_cast<int>(tmp_dword);
	}
	if(RegQueryValueEx(hKey_v, "ProbeMode", 0, NULL, (unsigned char*)&tmp_dword, &value_size) != ERROR_SUCCESS) {
		tmp_dword = probeMode;
		RegSetValueEx(hKey_v,"ProbeMode", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	} else {
		probeMode = static_cast<int>(tmp_dword);
	}
	{
		char orderBuf[128];
		DWORD orderSize = sizeof(orderBuf);
		if(RegQueryValueEx(hKey_v, "Order", 0, NULL, reinterpret_cast<unsigned char*>(orderBuf), &orderSize) != ERROR_SUCCESS) {
			RegSetValueEx(hKey_v,"Order", 0, REG_SZ, reinterpret_cast<const unsigned char*>(orderString.c_str()), static_cast<DWORD>(orderString.size() + 1));
		} else {
			orderBuf[orderSize > 0 ? orderSize - 1 : 0] = '\0';
			orderString = orderBuf;
		}
	}
	if(RegQueryValueEx(hKey_v, "Port", 0, NULL, (unsigned char*)&tmp_dword, &value_size) != ERROR_SUCCESS) {
		tmp_dword = port;
		RegSetValueEx(hKey_v,"Port", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	} else {
		port = static_cast<int>(tmp_dword);
	}
	if(RegQueryValueEx(hKey_v, "LocalPort", 0, NULL, (unsigned char*)&tmp_dword, &value_size) != ERROR_SUCCESS) {
		tmp_dword = static_cast<DWORD>(localPort);
		RegSetValueEx(hKey_v,"LocalPort", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	} else {
		localPort = static_cast<int>(tmp_dword);
	}
	
	r = RegCreateKeyEx(hKey,"LRU",0,NULL,0,KEY_ALL_ACCESS,NULL,&hKey_v,NULL);
	if(r != ERROR_SUCCESS)
		return FALSE;
	if(RegQueryValueEx(hKey_v, "NrLRU", 0, NULL, (unsigned char*)&tmp_dword, &value_size) != ERROR_SUCCESS) {
		tmp_dword = nrLRU;
		RegSetValueEx(hKey_v,"NrLRU", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	} else {
		char key_name[20];
		unsigned char str_host[255];
		nrLRU = tmp_dword;
		for(int i=0; i<maxLRU; i++) {
			sprintf(key_name,"Host%d", i+1);
			if(RegQueryValueEx(hKey_v, key_name, 0, NULL, NULL, &value_size) == ERROR_SUCCESS) {
				RegQueryValueEx(hKey_v, key_name, 0, NULL, str_host, &value_size);
				str_host[value_size]='\0';
				m_comboHost.AddString((CString)str_host);
			}
		}
	}
	m_comboHost.AddString(CString((LPCSTR)IDS_STRING_CLEAR_HISTORY));
	RegCloseKey(hKey_v);
	RegCloseKey(hKey);
	return TRUE;
}


//*****************************************************************************
// WinMTRDialog::OnSizing
//
//
//*****************************************************************************
void WinMTRDialog::OnSizing(UINT fwSide, LPRECT pRect)
{
	CDialog::OnSizing(fwSide, pRect);
	
	int iWidth = (pRect->right)-(pRect->left);
	int iHeight = (pRect->bottom)-(pRect->top);
	
	if(iWidth<638)
		pRect->right = pRect->left+638;
	if(iHeight<388)
		pRect->bottom = pRect->top+388;
}


//*****************************************************************************
// WinMTRDialog::OnSize
//
//
//*****************************************************************************
/// @todo (White-Tiger#1#): simplify it... use initial positions from "right" to calculate new position (no fix values here)
void WinMTRDialog::OnSize(UINT nType, int cx, int cy)
{
	CDialog::OnSize(nType, cx, cy);
	CRect rct,lb;
	if(!IsWindow(m_staticS.m_hWnd)) return;
	GetClientRect(&rct);
	m_staticS.GetWindowRect(&lb);
	ScreenToClient(&lb);
	m_staticS.SetWindowPos(NULL, lb.TopLeft().x, lb.TopLeft().y, rct.Width()-lb.TopLeft().x-8, lb.Height() , SWP_NOMOVE | SWP_NOZORDER);
	
	m_staticJ.GetWindowRect(&lb);
	ScreenToClient(&lb);
	m_staticJ.SetWindowPos(NULL, lb.TopLeft().x, lb.TopLeft().y, rct.Width() - 16, lb.Height(), SWP_NOMOVE | SWP_NOZORDER);
	
	const int rightMargin = 16;
	const int spacing = 4;
	int currentRight = rct.Width() - rightMargin;

	CButton* topRightButtons[] = {
		&m_buttonExit,
		&m_buttonOptions
	};
	for(auto* btn : topRightButtons) {
		btn->GetWindowRect(&lb);
		ScreenToClient(&lb);
		btn->SetWindowPos(NULL, currentRight - lb.Width(), lb.TopLeft().y, lb.Width(), lb.Height(), SWP_NOSIZE | SWP_NOZORDER);
		currentRight -= (lb.Width() + spacing);
	}

	currentRight = rct.Width() - rightMargin;
	CButton* exportButtons[] = {
		&m_buttonExpH,
		&m_buttonExpT,
		&m_buttonExpJson,
		&m_buttonExpCsv
	};
	for(auto* btn : exportButtons) {
		btn->GetWindowRect(&lb);
		ScreenToClient(&lb);
		btn->SetWindowPos(NULL, currentRight - lb.Width(), lb.TopLeft().y, lb.Width(), lb.Height(), SWP_NOSIZE | SWP_NOZORDER);
		currentRight -= (lb.Width() + spacing);
	}
	
	m_listMTR.GetWindowRect(&lb);
	ScreenToClient(&lb);
	m_listMTR.SetWindowPos(NULL, lb.TopLeft().x, lb.TopLeft().y, rct.Width() - 17, rct.Height() - lb.top - 25, SWP_NOMOVE | SWP_NOZORDER);

	CRect tabRect;
	m_tabView.GetWindowRect(&tabRect);
	ScreenToClient(&tabRect);
	m_tabView.SetWindowPos(NULL, tabRect.TopLeft().x, tabRect.TopLeft().y, rct.Width() - 17, tabRect.Height(), SWP_NOMOVE | SWP_NOZORDER);

	CWnd* statusGroup = GetDlgItem(IDC_STATUS_GROUP);
	if(statusGroup) {
		statusGroup->SetWindowPos(NULL, lb.TopLeft().x, lb.TopLeft().y, rct.Width() - 17, rct.Height() - lb.top - 25, SWP_NOMOVE | SWP_NOZORDER);
	}

	CWnd* metricsCard = GetDlgItem(IDC_STATUS_CARD_METRICS);
	CWnd* networkCard = GetDlgItem(IDC_STATUS_CARD_NETWORK);
	if(metricsCard && networkCard) {
		int left = lb.TopLeft().x + 5;
		int top = lb.TopLeft().y + 9;
		int height = rct.Height() - lb.top - 35;
		int width = rct.Width() - 27;
		int gap = 8;
		int networkWidth = 190;
		int metricsWidth = width - networkWidth - gap;
		metricsCard->SetWindowPos(NULL, left, top, metricsWidth, height, SWP_NOZORDER);
		networkCard->SetWindowPos(NULL, left + metricsWidth + gap, top, networkWidth, 70, SWP_NOZORDER);
	}
	
	RepositionBars(AFX_IDW_CONTROLBAR_FIRST, AFX_IDW_CONTROLBAR_LAST,
				   0, reposQuery, rct);
				   
	RepositionBars(AFX_IDW_CONTROLBAR_FIRST, AFX_IDW_CONTROLBAR_LAST, 0);
	
}


//*****************************************************************************
// WinMTRDialog::OnPaint
//
//
//*****************************************************************************
void WinMTRDialog::OnPaint()
{
	if(IsIconic()) {
		CPaintDC dc(this);
		
		SendMessage(WM_ICONERASEBKGND, (WPARAM) dc.GetSafeHdc(), 0);
		
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;
		
		dc.DrawIcon(x, y, m_hIcon);
	} else {
		CDialog::OnPaint();
	}
}


//*****************************************************************************
// WinMTRDialog::OnQueryDragIcon
//
//
//*****************************************************************************
HCURSOR WinMTRDialog::OnQueryDragIcon()
{
	return (HCURSOR) m_hIcon;
}


//*****************************************************************************
// WinMTRDialog::OnDblclkList
//
//*****************************************************************************
void WinMTRDialog::OnDblclkList(NMHDR* /*pNMHDR*/, LRESULT* pResult)
{
	*pResult=0;
	if(state==TRACING || state==IDLE || state==STOPPING) {
	
		POSITION pos = m_listMTR.GetFirstSelectedItemPosition();
		if(pos!=NULL) {
			int nItem = m_listMTR.GetNextSelectedItem(pos);
			WinMTRProperties wmtrprop;
			
			union {sockaddr* addr; sockaddr_in* addr4; sockaddr_in6* addr6;};
			addr=wmtrnet->GetAddr(nItem);
			if(!(addr4->sin_family==AF_INET&&addr4->sin_addr.s_addr) && !(addr6->sin6_family==AF_INET6&&(addr6->sin6_addr.u.Word[0]|addr6->sin6_addr.u.Word[1]|addr6->sin6_addr.u.Word[2]|addr6->sin6_addr.u.Word[3]|addr6->sin6_addr.u.Word[4]|addr6->sin6_addr.u.Word[5]|addr6->sin6_addr.u.Word[6]|addr6->sin6_addr.u.Word[7]))) {
				strcpy(wmtrprop.host,"");
				strcpy(wmtrprop.ip,"");
				wmtrnet->GetName(nItem, wmtrprop.comment);
			} else {
				wmtrnet->GetName(nItem, wmtrprop.host);
				if(getnameinfo(addr,sizeof(sockaddr_in6),wmtrprop.ip,40,NULL,0,NI_NUMERICHOST)) {
					*wmtrprop.ip='\0';
				}
				strcpy(wmtrprop.comment, "Host alive.");
			}
			
			wmtrprop.ping_avrg = (float)wmtrnet->GetAvg(nItem);
			wmtrprop.ping_last = (float)wmtrnet->GetLast(nItem);
			wmtrprop.ping_best = (float)wmtrnet->GetBest(nItem);
			wmtrprop.ping_worst = (float)wmtrnet->GetWorst(nItem);
			
			wmtrprop.pck_loss = wmtrnet->GetPercent(nItem);
			wmtrprop.pck_recv = wmtrnet->GetReturned(nItem);
			wmtrprop.pck_sent = wmtrnet->GetXmit(nItem);
			
			wmtrprop.DoModal();
		}
	}
}


//*****************************************************************************
// WinMTRDialog::SetHostName
//
//*****************************************************************************
void WinMTRDialog::SetHostName(const char* host)
{
	m_autostart = 1;
	strncpy(msz_defaulthostname, host, sizeof(msz_defaulthostname) - 1);
	msz_defaulthostname[sizeof(msz_defaulthostname) - 1] = '\0';
}


//*****************************************************************************
// WinMTRDialog::SetPingSize
//
//*****************************************************************************
void WinMTRDialog::SetPingSize(WORD ps)
{
	pingsize = ps;
}

//*****************************************************************************
// WinMTRDialog::SetMaxLRU
//
//*****************************************************************************
void WinMTRDialog::SetMaxLRU(int mlru)
{
	maxLRU = mlru;
}


//*****************************************************************************
// WinMTRDialog::SetInterval
//
//*****************************************************************************
void WinMTRDialog::SetInterval(float i)
{
	interval = i;
}

//*****************************************************************************
// WinMTRDialog::SetUseDNS
//
//*****************************************************************************
void WinMTRDialog::SetUseDNS(BOOL udns)
{
	useDNS = udns;
}

void WinMTRDialog::OnToggleShowIps()
{
	showIps = m_checkShowIps.GetCheck() == BST_CHECKED;
	HKEY hKey;
	DWORD tmp_dword;
	if(RegCreateKeyEx(HKEY_CURRENT_USER,"Software\\WinMTR\\Config",0,NULL,0,KEY_ALL_ACCESS,NULL,&hKey,NULL)==ERROR_SUCCESS) {
		tmp_dword = showIps ? 1 : 0;
		RegSetValueEx(hKey,"ShowIps", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
		RegCloseKey(hKey);
	}
	DisplayRedraw();
}

BOOL WinMTRDialog::PreTranslateMessage(MSG* pMsg)
{
	if(pMsg->message == WM_KEYDOWN) {
		const int key = static_cast<int>(pMsg->wParam);
		switch(key) {
		case 'P':
			paused = !paused;
			SetStatusText(paused ? "Paused (press P to resume)." : "Resumed.");
			return TRUE;
		case 'R':
			wmtrnet->ResetHops();
			m_listMTR.DeleteAllItems();
			SetStatusText("Counters reset.");
			return TRUE;
		case 'N':
			useDNS = !useDNS;
			SetStatusText(useDNS ? "DNS resolution enabled." : "DNS resolution disabled.");
			{
				HKEY hKey;
				DWORD tmp_dword;
				if(RegCreateKeyEx(HKEY_CURRENT_USER,"Software\\WinMTR\\Config",0,NULL,0,KEY_ALL_ACCESS,NULL,&hKey,NULL)==ERROR_SUCCESS) {
					tmp_dword = useDNS ? 1 : 0;
					RegSetValueEx(hKey,"UseDNS", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
					RegCloseKey(hKey);
				}
			}
			return TRUE;
		case 'B':
			showIps = !showIps;
			m_checkShowIps.SetCheck(showIps ? BST_CHECKED : BST_UNCHECKED);
			DisplayRedraw();
			return TRUE;
		case 'Q':
			Transit(EXIT);
			return TRUE;
		case 'U':
			probeMode = (probeMode + 1) % 3;
			if(probeMode == 1 && useIPv6 == 1) {
				SetStatusText("UDP mode supports IPv4 only. Using ICMP.");
				probeMode = 0;
			} else if(probeMode == 2 && useIPv6 == 1) {
				SetStatusText("TCP mode supports IPv4 only. Using ICMP.");
				probeMode = 0;
			} else {
				SetStatusText(probeMode == 2 ? "TCP mode selected." : (probeMode == 1 ? "UDP mode selected." : "ICMP mode selected."));
			}
			return TRUE;
		case 'Y':
			ipinfoMode = (ipinfoMode + 1) % 5;
			SetStatusText(IpinfoLabel(ipinfoMode));
			ApplyColumnOrder();
			DisplayRedraw();
			{
				HKEY hKey;
				DWORD tmp_dword;
				if(RegCreateKeyEx(HKEY_CURRENT_USER,"Software\\WinMTR\\Config",0,NULL,0,KEY_ALL_ACCESS,NULL,&hKey,NULL)==ERROR_SUCCESS) {
					tmp_dword = static_cast<DWORD>(ipinfoMode);
					RegSetValueEx(hKey,"IpinfoMode", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
					RegCloseKey(hKey);
				}
			}
			return TRUE;
		case 'Z':
			asnEnabled = !asnEnabled;
			SetStatusText(asnEnabled ? "ASN enabled." : "ASN disabled.");
			ApplyColumnOrder();
			DisplayRedraw();
			{
				HKEY hKey;
				DWORD tmp_dword;
				if(RegCreateKeyEx(HKEY_CURRENT_USER,"Software\\WinMTR\\Config",0,NULL,0,KEY_ALL_ACCESS,NULL,&hKey,NULL)==ERROR_SUCCESS) {
					tmp_dword = asnEnabled ? 1 : 0;
					RegSetValueEx(hKey,"AsnEnabled", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
					RegCloseKey(hKey);
				}
			}
			return TRUE;
		case 'O':
		case 'I':
		case 'F':
		case 'M':
		case 'S':
			OnOptions();
			return TRUE;
		case 'D':
			SetStatusText("Display modes are not supported yet.");
			return TRUE;
		case 'J':
			SetStatusText("Latency/jitter mode toggle is not supported yet.");
			return TRUE;
		default:
			break;
		}
	}
	return CDialog::PreTranslateMessage(pMsg);
}



//*****************************************************************************
// WinMTRDialog::OnRestart
//
//
//*****************************************************************************
void WinMTRDialog::OnRestart()
{
	// If clear history is selected, just clear the registry and listbox and return
	if(m_comboHost.GetCurSel() == m_comboHost.GetCount() - 1) {
		ClearHistory();
		return;
	}
	
	CString sHost;
	if(state == IDLE) {
		m_comboHost.GetWindowText(sHost);
		sHost.TrimLeft(); sHost.TrimRight();
		if(sHost.IsEmpty()) {
			AfxMessageBox("No host specified!");
			m_comboHost.SetFocus();
			return ;
		}
		if(probeMode == 1) {
			AfxMessageBox("UDP mode is not supported in the MFC UI yet. Using ICMP.");
			probeMode = 0;
		}
		if(probeMode == 2 && useIPv6 == 1) {
			AfxMessageBox("TCP mode supports IPv4 only in the MFC UI. Using ICMP.");
			probeMode = 0;
		}
		m_listMTR.DeleteAllItems();
		
		HKEY hKey; DWORD tmp_dword;
		if(RegCreateKeyEx(HKEY_CURRENT_USER,"Software\\WinMTR\\Config",0,NULL,0,KEY_ALL_ACCESS,NULL,&hKey,NULL)==ERROR_SUCCESS) {
			tmp_dword=m_checkIPv6.GetCheck();
			useIPv6=(unsigned char)tmp_dword;
			RegSetValueEx(hKey,"UseIPv6",0,REG_DWORD,(const unsigned char*)&tmp_dword,sizeof(DWORD));
			RegCloseKey(hKey);
		}
		if(InitMTRNet()) {
			if(m_comboHost.FindString(-1, sHost) == CB_ERR) {
				m_comboHost.InsertString(m_comboHost.GetCount() - 1,sHost);
				if(RegCreateKeyEx(HKEY_CURRENT_USER,"Software\\WinMTR\\LRU",0,NULL,0,KEY_ALL_ACCESS,NULL,&hKey,NULL)==ERROR_SUCCESS) {
					char key_name[20];
					if(++nrLRU>maxLRU) nrLRU=0;
					sprintf(key_name, "Host%d", nrLRU);
					RegSetValueEx(hKey,key_name, 0, REG_SZ, (const unsigned char*)(LPCTSTR)sHost, (DWORD)strlen((LPCTSTR)sHost)+1);
					tmp_dword = nrLRU;
					RegSetValueEx(hKey,"NrLRU", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
					RegCloseKey(hKey);
				}
			}
			Transit(TRACING);
		}
	} else {
		Transit(STOPPING);
	}
}


//*****************************************************************************
// WinMTRDialog::OnOptions
//
//
//*****************************************************************************
void WinMTRDialog::OnOptions()
{
	WinMTROptions optDlg(interval, pingsize, maxLRU, useDNS, maxHops, firstTtl, timeoutMs, tos, bitPattern, probeMode, port, localPort, orderString);
	if(IDOK == optDlg.DoModal()) {
	
		pingsize = (WORD)optDlg.GetPingSize();
		interval = optDlg.GetInterval();
		maxLRU = optDlg.GetMaxLRU();
		useDNS = optDlg.GetUseDNS();
		maxHops = optDlg.GetMaxHops();
		firstTtl = optDlg.GetFirstTtl();
		timeoutMs = optDlg.GetTimeoutMs();
		tos = optDlg.GetTos();
		bitPattern = optDlg.GetBitPattern();
		probeMode = optDlg.GetMode();
		port = optDlg.GetPort();
		localPort = optDlg.GetLocalPort();
		orderString = optDlg.GetOrder();
		if(maxHops <= 0) maxHops = DEFAULT_MAX_HOPS;
		if(firstTtl <= 0) firstTtl = DEFAULT_FIRST_TTL;
		if(firstTtl > maxHops) firstTtl = maxHops;
		if(timeoutMs <= 0) timeoutMs = DEFAULT_TIMEOUT_MS;
		if(port <= 0 || port > 65535) port = DEFAULT_PORT;
		if(localPort < 0 || localPort > 65535) localPort = DEFAULT_LOCALPORT;
		
		HKEY hKey;
		DWORD tmp_dword;
		
		if(RegCreateKeyEx(HKEY_CURRENT_USER,"Software\\WinMTR\\Config",0,NULL,0,KEY_ALL_ACCESS,NULL,&hKey,NULL)==ERROR_SUCCESS) {
			tmp_dword = pingsize;
			RegSetValueEx(hKey,"PingSize", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
			tmp_dword = maxLRU;
			RegSetValueEx(hKey,"MaxLRU", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
			tmp_dword = useDNS ? 1 : 0;
			RegSetValueEx(hKey,"UseDNS", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
			tmp_dword = (DWORD)(interval * 1000);
			RegSetValueEx(hKey,"Interval", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
			tmp_dword = timeoutMs;
			RegSetValueEx(hKey,"TimeoutMs", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
			tmp_dword = maxHops;
			RegSetValueEx(hKey,"MaxHops", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
			tmp_dword = firstTtl;
			RegSetValueEx(hKey,"FirstTtl", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
			tmp_dword = static_cast<DWORD>(tos);
			RegSetValueEx(hKey,"Tos", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
			tmp_dword = static_cast<DWORD>(bitPattern);
			RegSetValueEx(hKey,"BitPattern", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
			tmp_dword = static_cast<DWORD>(probeMode);
			RegSetValueEx(hKey,"ProbeMode", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
			tmp_dword = static_cast<DWORD>(port);
			RegSetValueEx(hKey,"Port", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
			tmp_dword = static_cast<DWORD>(localPort);
			RegSetValueEx(hKey,"LocalPort", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
			RegSetValueEx(hKey,"Order", 0, REG_SZ, reinterpret_cast<const unsigned char*>(orderString.c_str()), static_cast<DWORD>(orderString.size() + 1));
			RegCloseKey(hKey);
		}
		ApplyColumnOrder();
		if(maxLRU<nrLRU) {
			if(RegCreateKeyEx(HKEY_CURRENT_USER,"Software\\WinMTR\\LRU",0,NULL,0,KEY_ALL_ACCESS,NULL,&hKey,NULL)==ERROR_SUCCESS) {
				char key_name[20];
				for(int i = maxLRU; i<=nrLRU; ++i) {
					sprintf(key_name, "Host%d", i);
					RegDeleteValue(hKey,key_name);
				}
				nrLRU = maxLRU;
				tmp_dword = nrLRU;
				RegSetValueEx(hKey,"NrLRU", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
				RegCloseKey(hKey);
			}
		}
	}
}


//*****************************************************************************
// WinMTRDialog::OnCTTC
//
//
//*****************************************************************************
void WinMTRDialog::OnCTTC()
{
	std::ostringstream out;
	
	int nh = wmtrnet->GetMax();
	int startIndex = firstTtl > 0 ? firstTtl - 1 : 0;

	out << "Host";
	for(char code : orderFields) {
		out << " | " << OrderLabel(code);
	}
	if(asnEnabled) {
		out << " | " << IpinfoLabel(ipinfoMode);
	}
	out << "\r\n";

	for(int i = startIndex; i < nh; i++) {
		CString host = FormatHostLabel(i);
		out << host.GetString();
		for(char code : orderFields) {
			CString value = FormatFieldValue(code, i);
			out << " | " << value.GetString();
		}
		if(asnEnabled) {
			CString value = FormatIpInfo(i);
			out << " | " << value.GetString();
		}
		out << "\r\n";
	}

	CString source(out.str().c_str());
	
	HGLOBAL clipbuffer;
	char* buffer;
	
	OpenClipboard();
	EmptyClipboard();
	
	clipbuffer = GlobalAlloc(GMEM_DDESHARE, source.GetLength()+1);
	buffer = (char*)GlobalLock(clipbuffer);
	strcpy(buffer, LPCSTR(source));
	GlobalUnlock(clipbuffer);
	
	SetClipboardData(CF_TEXT,clipbuffer);
	CloseClipboard();
}


//*****************************************************************************
// WinMTRDialog::OnCHTC
//
//
//*****************************************************************************
void WinMTRDialog::OnCHTC()
{
	std::ostringstream html;
	
	int nh = wmtrnet->GetMax();
	int startIndex = firstTtl > 0 ? firstTtl - 1 : 0;
	
	html << "<html><head><title>WinMTR Statistics</title></head><body bgcolor=\"white\">\r\n";
	html << "<center><h2>WinMTR statistics</h2></center>\r\n";
	html << "<p align=\"center\"> <table border=\"1\" align=\"center\">\r\n";
	html << "<tr><td>Host</td>";
	for(char code : orderFields) {
		html << "<td>" << OrderLabel(code) << "</td>";
	}
	if(asnEnabled) {
		html << "<td>" << IpinfoLabel(ipinfoMode) << "</td>";
	}
	html << "</tr>\r\n";
	
	for(int i = startIndex; i < nh; i++) {
		CString host = FormatHostLabel(i);
		html << "<tr><td>" << host.GetString() << "</td>";
		for(char code : orderFields) {
			CString value = FormatFieldValue(code, i);
			html << "<td>" << value.GetString() << "</td>";
		}
		if(asnEnabled) {
			CString value = FormatIpInfo(i);
			html << "<td>" << value.GetString() << "</td>";
		}
		html << "</tr>\r\n";
	}
	
	html << "</table></body></html>\r\n";
	
	CString source(html.str().c_str());
	
	HGLOBAL clipbuffer;
	char* buffer;
	
	OpenClipboard();
	EmptyClipboard();
	
	clipbuffer = GlobalAlloc(GMEM_DDESHARE, source.GetLength()+1);
	buffer = (char*)GlobalLock(clipbuffer);
	strcpy(buffer, LPCSTR(source));
	GlobalUnlock(clipbuffer);
	
	SetClipboardData(CF_TEXT,clipbuffer);
	CloseClipboard();
}


//*****************************************************************************
// WinMTRDialog::OnEXPT
//
//
//*****************************************************************************
void WinMTRDialog::OnEXPT()
{
	TCHAR BASED_CODE szFilter[] = _T("Text Files (*.txt)|*.txt|All Files (*.*)|*.*||");
	
	CFileDialog dlg(FALSE,
					_T("TXT"),
					NULL,
					OFN_HIDEREADONLY | OFN_EXPLORER,
					szFilter,
					this);
	if(dlg.DoModal() == IDOK) {
		int nh = wmtrnet->GetMax();
		int startIndex = firstTtl > 0 ? firstTtl - 1 : 0;
		std::ostringstream out;
		
		out << "Host";
		for(char code : orderFields) {
			out << " | " << OrderLabel(code);
		}
		if(asnEnabled) {
			out << " | " << IpinfoLabel(ipinfoMode);
		}
		out << "\r\n";
		
		for(int i = startIndex; i < nh; i++) {
			CString host = FormatHostLabel(i);
			out << host.GetString();
			for(char code : orderFields) {
				CString value = FormatFieldValue(code, i);
				out << " | " << value.GetString();
			}
			if(asnEnabled) {
				CString value = FormatIpInfo(i);
				out << " | " << value.GetString();
			}
			out << "\r\n";
		}
		
		FILE* fp = fopen(dlg.GetPathName(), "wt");
		if(fp != NULL) {
			fprintf(fp, "%s", out.str().c_str());
			fclose(fp);
		}
	}
}


//*****************************************************************************
// WinMTRDialog::OnEXPCSV
//
//
//*****************************************************************************
void WinMTRDialog::OnEXPCSV()
{
	TCHAR BASED_CODE szFilter[] = _T("CSV Files (*.csv)|*.csv|All Files (*.*)|*.*||");

	CFileDialog dlg(FALSE,
					_T("CSV"),
					NULL,
					OFN_HIDEREADONLY | OFN_EXPLORER,
					szFilter,
					this);
	if(dlg.DoModal() == IDOK) {
		char buf[255];
		int nh = wmtrnet->GetMax();
		int startIndex = firstTtl > 0 ? firstTtl - 1 : 0;

	std::ostringstream csv;
	csv << "Host";
	for(char code : orderFields) {
		csv << "," << OrderLabel(code);
	}
	if(asnEnabled) {
		csv << "," << IpinfoLabel(ipinfoMode);
	}
	csv << "\r\n";
	csv << "FieldCodes";
	for(char code : orderFields) {
		csv << "," << code;
	}
	if(asnEnabled) {
		csv << ",IPINFO";
	}
	csv << "\r\n";

		for(int i = startIndex; i < nh; i++) {
			CString host = FormatHostLabel(i);
			csv << EscapeCsvField(host.GetString());
			for(char code : orderFields) {
				CString value = FormatFieldValue(code, i);
				csv << "," << EscapeCsvField(value.GetString());
			}
			if(asnEnabled) {
				CString value = FormatIpInfo(i);
				csv << "," << EscapeCsvField(value.GetString());
			}
			csv << "\r\n";
		}

		FILE* fp = fopen(dlg.GetPathName(), "wt");
		if(fp != NULL) {
			fprintf(fp, "%s", csv.str().c_str());
			fclose(fp);
		}
	}
}


//*****************************************************************************
// WinMTRDialog::OnEXPH
//
//
//*****************************************************************************
void WinMTRDialog::OnEXPH()
{
	TCHAR BASED_CODE szFilter[] = _T("HTML Files (*.htm, *.html)|*.htm;*.html|All Files (*.*)|*.*||");
	
	CFileDialog dlg(FALSE,
					_T("HTML"),
					NULL,
					OFN_HIDEREADONLY | OFN_EXPLORER,
					szFilter,
					this);
					
	if(dlg.DoModal() == IDOK) {
	
		char buf[255], t_buf[1000], f_buf[255*100];
		
		int nh = wmtrnet->GetMax();
		int startIndex = firstTtl > 0 ? firstTtl - 1 : 0;
		
		strcpy(f_buf, "<html><head><title>WinMTR Statistics</title></head><body bgcolor=\"white\">\r\n");
		sprintf(t_buf, "<center><h2>WinMTR statistics</h2></center>\r\n");
		strcat(f_buf, t_buf);
		
		sprintf(t_buf, "<p align=\"center\"> <table border=\"1\" align=\"center\">\r\n");
		strcat(f_buf, t_buf);
		
		sprintf(t_buf, "<tr><td>Host</td>");
		strcat(f_buf, t_buf);
		for(char code : orderFields) {
			sprintf(t_buf, " <td>%s</td>", OrderLabel(code));
			strcat(f_buf, t_buf);
		}
		if(asnEnabled) {
			sprintf(t_buf, " <td>%s</td>", IpinfoLabel(ipinfoMode));
			strcat(f_buf, t_buf);
		}
		strcat(f_buf, "</tr>\r\n");
		
		for(int i = startIndex; i < nh; i++) {
			wmtrnet->GetName(i, buf);
			if(strcmp(buf,"")==0) strcpy(buf,"No response from host");
			
			CString host = FormatHostLabel(i);
			sprintf(t_buf, "<tr><td>%s</td>", host.GetString());
			strcat(f_buf, t_buf);
			for(char code : orderFields) {
				CString value = FormatFieldValue(code, i);
				sprintf(t_buf, " <td>%s</td>", value.GetString());
				strcat(f_buf, t_buf);
			}
			if(asnEnabled) {
				CString value = FormatIpInfo(i);
				sprintf(t_buf, " <td>%s</td>", value.GetString());
				strcat(f_buf, t_buf);
			}
			strcat(f_buf, "</tr>\r\n");
		}
		
		sprintf(t_buf, "</table></body></html>\r\n");
		strcat(f_buf, t_buf);
		
		FILE* fp = fopen(dlg.GetPathName(), "wt");
		if(fp != NULL) {
			fprintf(fp, "%s", f_buf);
			fclose(fp);
		}
	}
	
	
}


//*****************************************************************************
// WinMTRDialog::OnEXPJSON
//
//
//*****************************************************************************
void WinMTRDialog::OnEXPJSON()
{
	TCHAR BASED_CODE szFilter[] = _T("JSON Files (*.json)|*.json|All Files (*.*)|*.*||");

	CFileDialog dlg(FALSE,
					_T("JSON"),
					NULL,
					OFN_HIDEREADONLY | OFN_EXPLORER,
					szFilter,
					this);

	if(dlg.DoModal() == IDOK) {
		char buf[255];
		int nh = wmtrnet->GetMax();
		int startIndex = firstTtl > 0 ? firstTtl - 1 : 0;

		CString target;
		m_comboHost.GetWindowText(target);

		std::ostringstream json;
		json << "{\r\n";
		json << "  \"target\": \"" << EscapeJsonString((LPCTSTR)target) << "\",\r\n";
		json << "  \"fields\": [";
		for(size_t f = 0; f < orderFields.size(); ++f) {
			json << "\"" << OrderLabel(orderFields[f]) << "\"";
			if(f + 1 < orderFields.size()) json << ", ";
		}
		if(asnEnabled) {
			if(!orderFields.empty()) json << ", ";
			json << "\"" << IpinfoLabel(ipinfoMode) << "\"";
		}
		json << "],\r\n";
		json << "  \"field_codes\": [";
		for(size_t f = 0; f < orderFields.size(); ++f) {
			json << "\"" << orderFields[f] << "\"";
			if(f + 1 < orderFields.size()) json << ", ";
		}
		if(asnEnabled) {
			if(!orderFields.empty()) json << ", ";
			json << "\"IPINFO\"";
		}
		json << "],\r\n";
		json << "  \"ipinfo_mode\": " << ipinfoMode << ",\r\n";
		json << "  \"asn_enabled\": " << (asnEnabled ? "true" : "false") << ",\r\n";
		json << "  \"hops\": [\r\n";

		for(int i = startIndex; i < nh; i++) {
			CString host = FormatHostLabel(i);

			json << "    {\r\n";
			json << "      \"host\": \"" << EscapeJsonString(host.GetString()) << "\",\r\n";
			json << "      \"values\": [";
			for(size_t f = 0; f < orderFields.size(); ++f) {
				CString value = FormatFieldValue(orderFields[f], i);
				json << "\"" << EscapeJsonString(value.GetString()) << "\"";
				if(f + 1 < orderFields.size()) json << ", ";
			}
			if(asnEnabled) {
				if(!orderFields.empty()) json << ", ";
				CString value = FormatIpInfo(i);
				json << "\"" << EscapeJsonString(value.GetString()) << "\"";
			}
			json << "]\r\n";
			json << "    }";
			if(i < nh - 1) json << ",";
			json << "\r\n";
		}

		json << "  ]\r\n";
		json << "}\r\n";

		FILE* fp = fopen(dlg.GetPathName(), "wt");
		if(fp != NULL) {
			fprintf(fp, "%s", json.str().c_str());
			fclose(fp);
		}
	}
}

HBRUSH WinMTRDialog::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CDialog::OnCtlColor(pDC, pWnd, nCtlColor);
	if(!pWnd) return hbr;

	int id = pWnd->GetDlgCtrlID();
	bool isMetrics = false;
	bool isNetwork = false;
	bool isValue = false;

	switch(id) {
	case IDC_STATUS_CARD_METRICS:
	case IDC_STATUS_RESP_LABEL:
	case IDC_STATUS_LAG_ROUTER_LABEL:
	case IDC_STATUS_LAG_INET_LABEL:
	case IDC_STATUS_AVG_LABEL:
	case IDC_STATUS_BEST_LABEL:
	case IDC_STATUS_WORST_LABEL:
	case IDC_STATUS_LATENCY_LABEL:
	case IDC_STATUS_JITTER_LABEL:
	case IDC_STATUS_LOSS_LABEL:
	case IDC_STATUS_RESP_VALUE:
	case IDC_STATUS_LAG_ROUTER_VALUE:
	case IDC_STATUS_LAG_INET_VALUE:
	case IDC_STATUS_AVG_VALUE:
	case IDC_STATUS_BEST_VALUE:
	case IDC_STATUS_WORST_VALUE:
	case IDC_STATUS_LATENCY_VALUE:
	case IDC_STATUS_JITTER_VALUE:
	case IDC_STATUS_LOSS_VALUE:
		isMetrics = true;
		break;
	case IDC_STATUS_CARD_NETWORK:
	case IDC_STATUS_LAN_LABEL:
	case IDC_STATUS_WAN_LABEL:
	case IDC_STATUS_ASN_LABEL:
	case IDC_STATUS_LAN_VALUE:
	case IDC_STATUS_WAN_VALUE:
	case IDC_STATUS_ASN_VALUE:
		isNetwork = true;
		break;
	default:
		break;
	}
	if(id == IDC_STATUS_RESP_VALUE ||
		id == IDC_STATUS_LAG_ROUTER_VALUE ||
		id == IDC_STATUS_LAG_INET_VALUE ||
		id == IDC_STATUS_AVG_VALUE ||
		id == IDC_STATUS_BEST_VALUE ||
		id == IDC_STATUS_WORST_VALUE ||
		id == IDC_STATUS_LATENCY_VALUE ||
		id == IDC_STATUS_JITTER_VALUE ||
		id == IDC_STATUS_LOSS_VALUE ||
		id == IDC_STATUS_LAN_VALUE ||
		id == IDC_STATUS_WAN_VALUE ||
		id == IDC_STATUS_ASN_VALUE) {
		isValue = true;
	}

	if(isMetrics || isNetwork) {
		pDC->SetBkMode(OPAQUE);
		if(isMetrics) {
			pDC->SetBkColor(m_metricsCardColor);
			if(id == IDC_STATUS_CARD_METRICS && nCtlColor == CTLCOLOR_BTN) {
				return m_metricsCardBrush;
			}
			if(nCtlColor == CTLCOLOR_STATIC) {
				pDC->SetTextColor(isValue ? m_statusValueColor : m_statusTextColor);
				return m_metricsCardBrush;
			}
		} else if(isNetwork) {
			pDC->SetBkColor(m_networkCardColor);
			if(id == IDC_STATUS_CARD_NETWORK && nCtlColor == CTLCOLOR_BTN) {
				return m_networkCardBrush;
			}
			if(nCtlColor == CTLCOLOR_STATIC) {
				pDC->SetTextColor(isValue ? m_statusValueColor : m_statusTextColor);
				return m_networkCardBrush;
			}
		}
	}

	return hbr;
}

void WinMTRDialog::OnTabSelchange(NMHDR* pNMHDR, LRESULT* pResult)
{
	ShowTab(m_tabView.GetCurSel());
	*pResult = 0;
}


//*****************************************************************************
// WinMTRDialog::WinMTRDialog
//
//
//*****************************************************************************
void WinMTRDialog::OnCancel()
{
}


//*****************************************************************************
// WinMTRDialog::DisplayRedraw
//
//
//*****************************************************************************
int WinMTRDialog::DisplayRedraw()
{
	char buf[255], nr_crt[255];
	int nh = wmtrnet->GetMax();
	int startIndex = firstTtl > 0 ? firstTtl - 1 : 0;
	if(startIndex < 0) startIndex = 0;
	int displayCount = nh - startIndex;
	if(displayCount < 0) displayCount = 0;
	while(m_listMTR.GetItemCount() > displayCount) m_listMTR.DeleteItem(m_listMTR.GetItemCount() - 1);
	
	int rowIndex = 0;
	for(int i = startIndex; i < nh; ++i, ++rowIndex) {
	
		CString hostLabel = FormatHostLabel(i);
		strncpy(buf, hostLabel, sizeof(buf) - 1);
		buf[sizeof(buf) - 1] = '\0';
		
		sprintf(nr_crt, "%d", i+1);
		if(m_listMTR.GetItemCount() <= rowIndex)
			m_listMTR.InsertItem(rowIndex, buf);
		else
			m_listMTR.SetItem(rowIndex, 0, LVIF_TEXT, buf, 0, 0, 0, 0);
			
		m_listMTR.SetItem(rowIndex, 1, LVIF_TEXT, nr_crt, 0, 0, 0, 0);
		
		int colIndex = 2;
		for(char code : orderFields) {
			CString value = FormatFieldValue(code, i);
			m_listMTR.SetItem(rowIndex, colIndex, LVIF_TEXT, value, 0, 0, 0, 0);
			++colIndex;
		}
		if(asnEnabled) {
			CString value = FormatIpInfo(i);
			m_listMTR.SetItem(rowIndex, colIndex, LVIF_TEXT, value, 0, 0, 0, 0);
		}
		
		
	}
	
	return 0;
}


//*****************************************************************************
// WinMTRDialog::InitMTRNet
//
//
//*****************************************************************************
int WinMTRDialog::InitMTRNet()
{
	char hostname[255];
	char buf[255];
	m_comboHost.GetWindowText(hostname, 255);
	
	sprintf(buf, "Resolving host %s...", hostname);
	SetStatusText(buf);
	
	addrinfo nfofilter= {0};
	addrinfo* anfo;
	if(wmtrnet->hasIPv6) {
		switch(useIPv6) {
		case 0:
			nfofilter.ai_family=AF_INET; break;
		case 1:
			nfofilter.ai_family=AF_INET6; break;
		default:
			nfofilter.ai_family=AF_UNSPEC;
		}
	}
	nfofilter.ai_socktype=SOCK_RAW;
	nfofilter.ai_flags=AI_NUMERICSERV|AI_ADDRCONFIG;//|AI_V4MAPPED;
	if(getaddrinfo(hostname,NULL,&nfofilter,&anfo)||!anfo) {
		SetStatusText(CString((LPCSTR)IDS_STRING_SB_NAME));
		AfxMessageBox("Unable to resolve hostname.");
		return 0;
	}
	freeaddrinfo(anfo);
	return 1;
}


//*****************************************************************************
// PingThread
//
//
//*****************************************************************************
void PingThread(void* p)
{
	WinMTRDialog* wmtrdlg = (WinMTRDialog*)p;
	WaitForSingleObject(wmtrdlg->traceThreadMutex, INFINITE);
	
	char hostname[255];
	wmtrdlg->m_comboHost.GetWindowText(hostname, 255);
	
	addrinfo nfofilter= {0};
	addrinfo* anfo;
	if(wmtrdlg->wmtrnet->hasIPv6) {
		switch(wmtrdlg->useIPv6) {
		case 0:
			nfofilter.ai_family=AF_INET; break;
		case 1:
			nfofilter.ai_family=AF_INET6; break;
		default:
			nfofilter.ai_family=AF_UNSPEC;
		}
	}
	nfofilter.ai_socktype=SOCK_RAW;
	nfofilter.ai_flags=AI_NUMERICSERV|AI_ADDRCONFIG;//|AI_V4MAPPED;
	if(getaddrinfo(hostname,NULL,&nfofilter,&anfo)||!anfo) { //we use first address returned
		AfxMessageBox("Unable to resolve hostname. (again)");
		ReleaseMutex(wmtrdlg->traceThreadMutex);
		return;
	}
	if(wmtrdlg->probeMode == 2) {
		if(anfo->ai_family == AF_INET) {
			wmtrdlg->wmtrnet->DoTraceTcp(reinterpret_cast<sockaddr_in*>(anfo->ai_addr));
		} else {
			AfxMessageBox("TCP mode supports IPv4 only in the MFC UI.");
			wmtrdlg->wmtrnet->DoTrace(anfo->ai_addr);
		}
	} else if(wmtrdlg->probeMode == 1) {
		if(anfo->ai_family == AF_INET) {
			wmtrdlg->wmtrnet->DoTraceUdp(reinterpret_cast<sockaddr_in*>(anfo->ai_addr));
		} else {
			AfxMessageBox("UDP mode supports IPv4 only in the MFC UI.");
			wmtrdlg->wmtrnet->DoTrace(anfo->ai_addr);
		}
	} else {
		wmtrdlg->wmtrnet->DoTrace(anfo->ai_addr);
	}
	freeaddrinfo(anfo);
	ReleaseMutex(wmtrdlg->traceThreadMutex);
}

static unsigned WINAPI WanInfoThread(void* p)
{
	WinMTRDialog* dlg = reinterpret_cast<WinMTRDialog*>(p);
	std::string v4;
	std::string v6;
	std::string asn;

	std::string ip;
	std::string asnTmp;
	std::string orgTmp;

	if(TryFetchWanInfo(L"ipinfo.io", L"/json", ip, asnTmp, orgTmp) ||
	   TryFetchWanInfo(L"ipapi.co", L"/json/", ip, asnTmp, orgTmp)) {
		v4 = ip;
		if(!orgTmp.empty()) {
			asn = orgTmp;
		} else {
			asn = asnTmp;
		}
	}

	ip.clear();
	asnTmp.clear();
	orgTmp.clear();

	if(TryFetchWanInfo(L"v6.ipinfo.io", L"/json", ip, asnTmp, orgTmp) ||
	   TryFetchWanInfo(L"v6.ifconfig.co", L"/json", ip, asnTmp, orgTmp)) {
		v6 = ip;
		if(asn.empty()) {
			if(!orgTmp.empty()) {
				asn = orgTmp;
			} else {
				asn = asnTmp;
			}
		}
	}

	{
		std::lock_guard<std::mutex> lock(dlg->ipInfoMutex);
		dlg->wanIpv4 = v4.c_str();
		dlg->wanIpv6 = v6.c_str();
		dlg->wanAsn = asn.c_str();
		HANDLE threadHandle = dlg->wanInfoThread;
		dlg->wanInfoThread = NULL;
		if(threadHandle) CloseHandle(threadHandle);
	}

	if(dlg->m_hWnd) {
		PostMessage(dlg->m_hWnd, WM_APP_UPDATE_IPINFO, 0, 0);
	}
	return 0;
}



void WinMTRDialog::OnCbnSelchangeComboHost()
{
}

void WinMTRDialog::ClearHistory()
{
	HKEY hKey;
	DWORD tmp_dword;
	char key_name[20];
	
	if(RegCreateKeyEx(HKEY_CURRENT_USER,"Software\\WinMTR\\LRU",0,NULL,0,KEY_ALL_ACCESS,NULL,&hKey,NULL)!=ERROR_SUCCESS) {
		return;
	}
	
	for(int i = 0; i<=nrLRU; i++) {
		sprintf(key_name, "Host%d", i);
		RegDeleteValue(hKey,key_name);
	}
	nrLRU = 0;
	tmp_dword = nrLRU;
	RegSetValueEx(hKey,"NrLRU", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	RegCloseKey(hKey);
	
	m_comboHost.Clear();
	m_comboHost.ResetContent();
	m_comboHost.AddString(CString((LPCSTR)IDS_STRING_CLEAR_HISTORY));
}

void WinMTRDialog::OnCbnSelendokComboHost()
{
}


void WinMTRDialog::OnCbnCloseupComboHost()
{
	if(m_comboHost.GetCurSel() == m_comboHost.GetCount() - 1) {
		ClearHistory();
	}
}

void WinMTRDialog::Transit(STATES new_state)
{
	switch(new_state) {
	case IDLE:
		switch(state) {
		case STOPPING:
			transition = STOPPING_TO_IDLE;
			break;
		case IDLE:
			transition = IDLE_TO_IDLE;
			break;
		default:
			TRACE_MSG("Received state IDLE after " << state);
			return;
		}
		state = IDLE;
		break;
	case TRACING:
		switch(state) {
		case IDLE:
			transition = IDLE_TO_TRACING;
			break;
		case TRACING:
			transition = TRACING_TO_TRACING;
			break;
		default:
			TRACE_MSG("Received state TRACING after " << state);
			return;
		}
		state = TRACING;
		break;
	case STOPPING:
		switch(state) {
		case STOPPING:
			transition = STOPPING_TO_STOPPING;
			break;
		case TRACING:
			transition = TRACING_TO_STOPPING;
			break;
		default:
			TRACE_MSG("Received state STOPPING after " << state);
			return;
		}
		state = STOPPING;
		break;
	case EXIT:
		switch(state) {
		case IDLE:
			transition = IDLE_TO_EXIT;
			break;
		case STOPPING:
			transition = STOPPING_TO_EXIT;
			break;
		case TRACING:
			transition = TRACING_TO_EXIT;
			break;
		case EXIT:
			break;
		default:
			TRACE_MSG("Received state EXIT after " << state);
			return;
		}
		state = EXIT;
		break;
	default:
		TRACE_MSG("Received state " << state);
	}
	
	// modify controls according to new state
	switch(transition) {
	case IDLE_TO_IDLE:
		// nothing to be done
		break;
	case IDLE_TO_TRACING:
		m_buttonStart.EnableWindow(FALSE);
		m_buttonStart.SetWindowText("Stop");
		m_comboHost.EnableWindow(FALSE);
		m_checkIPv6.EnableWindow(FALSE);
		m_buttonOptions.EnableWindow(FALSE);
		SetStatusText("Double click on host name for more information.");
		_beginthread(PingThread, 0 , this);
		m_buttonStart.EnableWindow(TRUE);
		break;
	case IDLE_TO_EXIT:
		m_buttonStart.EnableWindow(FALSE);
		m_comboHost.EnableWindow(FALSE);
		m_buttonOptions.EnableWindow(FALSE);
		break;
	case STOPPING_TO_IDLE:
		DisplayRedraw();
		m_buttonStart.EnableWindow(TRUE);
		SetStatusText(CString((LPCSTR)IDS_STRING_SB_NAME));
		m_buttonStart.SetWindowText("Start");
		m_comboHost.EnableWindow(TRUE);
		m_checkIPv6.EnableWindow(TRUE);
		m_buttonOptions.EnableWindow(TRUE);
		m_comboHost.SetFocus();
		break;
	case STOPPING_TO_STOPPING:
		DisplayRedraw();
		break;
	case STOPPING_TO_EXIT:
		break;
	case TRACING_TO_TRACING:
		DisplayRedraw();
		break;
	case TRACING_TO_STOPPING:
		m_buttonStart.EnableWindow(FALSE);
		wmtrnet->StopTrace();
		SetStatusText("Waiting for last packets in order to stop trace ...");
		DisplayRedraw();
		break;
	case TRACING_TO_EXIT:
		m_buttonStart.EnableWindow(FALSE);
		wmtrnet->StopTrace();
		SetStatusText("Waiting for last packets in order to stop trace ...");
		break;
	default:
		TRACE_MSG("Unknown transition " << transition);
	}
}


void WinMTRDialog::OnTimer(UINT_PTR nIDEvent)
{
	static unsigned int call_count=0;
	if(state == EXIT && WaitForSingleObject(traceThreadMutex, 0) == WAIT_OBJECT_0) {
		ReleaseMutex(traceThreadMutex);
		OnOK();
	}
	
	if(WaitForSingleObject(traceThreadMutex, 0) == WAIT_OBJECT_0) {
		ReleaseMutex(traceThreadMutex);
		Transit(IDLE);
	} else if((++call_count&5)==5) {
		if(state==TRACING) Transit(TRACING);
		else if(state==STOPPING) Transit(STOPPING);
	}

	UpdateStatusTab();
	
	CDialog::OnTimer(nIDEvent);
}


void WinMTRDialog::OnClose()
{
	Transit(EXIT);
}


void WinMTRDialog::OnBnClickedCancel()
{
	Transit(EXIT);
}
