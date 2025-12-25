//*****************************************************************************
// FILE:            WinMTROptions.h
//
//
// DESCRIPTION:
//
//
// NOTES:
//
//
//*****************************************************************************

#ifndef WINMTROPTIONS_H_
#define WINMTROPTIONS_H_

#include <string>


//*****************************************************************************
// CLASS:  WinMTROptions
//
//
//*****************************************************************************

class WinMTROptions : public CDialog
{
public:
	WinMTROptions(double interval,
	              int pingsize,
	              int maxLRU,
	              BOOL useDNS,
	              int maxHops,
	              int firstTtl,
	              int timeoutMs,
	              int tos,
	              int bitPattern,
	              int mode,
	              int port,
	              int localPort,
	              const std::string& order,
	              CWnd* pParent=NULL) :
		interval(interval),
		pingsize(pingsize),
		maxLRU(maxLRU),
		useDNS(useDNS),
		maxHops(maxHops),
		firstTtl(firstTtl),
		timeoutMs(timeoutMs),
		tos(tos),
		bitPattern(bitPattern),
		mode(mode),
		port(port),
		localPort(localPort),
		order(order),
		CDialog(WinMTROptions::IDD, pParent) {};
		
	double GetInterval()			{ return interval; };
	int GetPingSize()				{ return pingsize; };
	int GetMaxLRU()					{ return maxLRU; };
	BOOL GetUseDNS()				{ return useDNS; };
	int GetMaxHops()				{ return maxHops; };
	int GetFirstTtl()				{ return firstTtl; };
	int GetTimeoutMs()				{ return timeoutMs; };
	int GetTos()					{ return tos; };
	int GetBitPattern()				{ return bitPattern; };
	int GetMode()					{ return mode; };
	int GetPort()					{ return port; };
	int GetLocalPort()				{ return localPort; };
	std::string GetOrder()			{ return order; };
	
	enum { IDD = IDD_DIALOG_OPTIONS };
	CEdit	m_editSize;
	CEdit	m_editInterval;
	CEdit	m_editMaxLRU;
	CEdit	m_editMaxHops;
	CEdit	m_editFirstTtl;
	CEdit	m_editTimeout;
	CEdit	m_editTos;
	CEdit	m_editBitPattern;
	CEdit	m_editPort;
	CEdit	m_editLocalPort;
	CEdit	m_editOrder;
	CButton	m_checkDNS;
	CComboBox m_comboMode;
	
protected:
	virtual void DoDataExchange(CDataExchange* pDX);
	
	virtual BOOL OnInitDialog();
	virtual void OnOK();
	
	afx_msg void OnLicense();
	
	DECLARE_MESSAGE_MAP()
	
private:
	double	interval;
	int		pingsize;
	int		maxLRU;
	BOOL	useDNS;
	int		maxHops;
	int		firstTtl;
	int		timeoutMs;
	int		tos;
	int		bitPattern;
	int		mode;
	int		port;
	int		localPort;
	std::string order;
};

#endif // ifndef WINMTROPTIONS_H_
