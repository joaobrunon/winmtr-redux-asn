//*****************************************************************************
// FILE:            WinMTRDialog.h
//
//
// DESCRIPTION:
//
//
// NOTES:
//
//
//*****************************************************************************

#ifndef WINMTRDIALOG_H_
#define WINMTRDIALOG_H_

#define WINMTR_DIALOG_TIMER 100

#include "WinMTRStatusBar.h"
#include "WinMTRNet.h"
#include "afxlinkctrl.h"
#include <string>
#include <vector>
#include <mutex>

//*****************************************************************************
// CLASS:  WinMTRDialog
//
//
//*****************************************************************************

class WinMTRDialog : public CDialog
{
public:
	WinMTRDialog(CWnd* pParent = NULL);
	~WinMTRDialog();
	
	enum { IDD = IDD_WINMTR_DIALOG };
	
	afx_msg BOOL InitRegistry();
	
	WinMTRStatusBar	statusBar;
	
	enum STATES {
		IDLE,
		TRACING,
		STOPPING,
		EXIT
	};
	
	enum STATE_TRANSITIONS {
		IDLE_TO_IDLE,
		IDLE_TO_TRACING,
		IDLE_TO_EXIT,
		TRACING_TO_TRACING,
		TRACING_TO_STOPPING,
		TRACING_TO_EXIT,
		STOPPING_TO_IDLE,
		STOPPING_TO_STOPPING,
		STOPPING_TO_EXIT
	};
	
	CButton	m_buttonOptions;
	CButton	m_buttonExit;
	CButton	m_buttonStart;
	CComboBox m_comboHost;
	CButton m_checkIPv6;
	CButton m_checkShowIps;
	CListCtrl m_listMTR;
	CTabCtrl m_tabView;
	CMFCLinkCtrl m_buttonAppnor;
	CFont m_uiFont;
	CFont m_statusValueFont;
	CFont m_statusSmallFont;
	CBrush m_metricsCardBrush;
	CBrush m_networkCardBrush;
	COLORREF m_metricsCardColor;
	COLORREF m_networkCardColor;
	COLORREF m_statusTextColor;
	COLORREF m_statusValueColor;
	bool layoutBaseCaptured;
	CRect baseStaticJRect;
	CRect baseTabRect;
	CRect baseListRect;
	CRect baseStatusGroupRect;
	int baseExportTop;
	int baseExportLeft;
	int baseExportHeight;
	bool statusAutoTrace;
	bool initCompleted;
	bool initInProgress;
	
	CStatic	m_staticS;
	CStatic	m_staticJ;
	
	CButton	m_buttonExpT;
	CButton	m_buttonExpH;
	CButton	m_buttonExpCsv;
	CButton	m_buttonExpJson;
	
	int InitMTRNet();
	
	int DisplayRedraw();
	void Transit(STATES new_state);
	
	STATES				state;
	STATE_TRANSITIONS	transition;
	HANDLE				traceThreadMutex;
	double				interval;
	bool				hasIntervalFromCmdLine;
	WORD				pingsize;
	bool				hasPingsizeFromCmdLine;
	int					maxLRU;
	bool				hasMaxLRUFromCmdLine;
	int					maxHops;
	int					firstTtl;
	int					timeoutMs;
	int					tos;
	int					bitPattern;
	int					probeMode;
	int					port;
	int					localPort;
	std::string			orderString;
	std::vector<char>	orderFields;
	bool				asnEnabled;
	int					ipinfoMode;
	bool				showIps;
	bool				paused;
	int					nrLRU;
	BOOL				useDNS;
	bool				hasUseDNSFromCmdLine;
	unsigned char		useIPv6;
	bool				hasUseIPv6FromCmdLine;
	WinMTRNet*			wmtrnet;
	std::mutex			ipInfoMutex;
	CString				localIpv4;
	CString				localIpv6;
	CString				wanIpv4;
	CString				wanIpv6;
	CString				wanAsn;
	HANDLE				wanInfoThread;
	
	void SetHostName(const char* host);
	void SetInterval(float i);
	void SetPingSize(WORD ps);
	void SetMaxLRU(int mlru);
	void SetUseDNS(BOOL udns);
	
protected:
	virtual void DoDataExchange(CDataExchange* pDX);
	virtual BOOL PreTranslateMessage(MSG* pMsg);
	void ApplyColumnOrder();
	void AdjustListColumns();
	std::vector<char> ParseOrderFields(const std::string& order) const;
	CString FormatFieldValue(char code, int index) const;
	CString FormatIpInfo(int index) const;
	CString FormatHostLabel(int index) const;
	void RefreshLocalIpInfo();
	void StartWanInfoRefresh();
	void UpdateIpInfoStatusBar();
	afx_msg LRESULT OnUpdateIpInfo(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnStartStatusTrace(WPARAM wParam, LPARAM lParam);
	void SetStatusText(const CString& text);
	void UpdateStatusTab();
	void ShowTab(int index);
	void ApplyUiFont();
	void ApplyStatusFonts();
	void PrepareStatusCards();
	void DrawStatusCard(LPDRAWITEMSTRUCT drawItemStruct, COLORREF fillColor, const CString& title, const CString& value);
	CString m_statusCardTitles[12];
	CString m_statusCardValues[12];
	
	int m_autostart;
	char msz_defaulthostname[1000];
	
	HICON m_hIcon;
	
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg void OnSize(UINT, int, int);
	afx_msg void OnSizing(UINT, LPRECT);
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnRestart();
	afx_msg void OnOptions();
	afx_msg void OnToggleShowIps();
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	afx_msg void OnDrawItem(int nIDCtl, LPDRAWITEMSTRUCT lpDrawItemStruct);
	virtual void OnCancel();
	
	afx_msg void OnCTTC();
	afx_msg void OnCHTC();
	afx_msg void OnEXPT();
	afx_msg void OnEXPH();
	afx_msg void OnEXPCSV();
	afx_msg void OnEXPJSON();
	afx_msg void OnTabSelchange(NMHDR* pNMHDR, LRESULT* pResult);
	
	afx_msg void OnDblclkList(NMHDR* pNMHDR, LRESULT* pResult);
	
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnCbnSelchangeComboHost();
	afx_msg void OnCbnSelendokComboHost();
private:
	void ClearHistory();
public:
	afx_msg void OnCbnCloseupComboHost();
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	afx_msg void OnClose();
	afx_msg void OnBnClickedCancel();
};

#endif // ifndef WINMTRDIALOG_H_
