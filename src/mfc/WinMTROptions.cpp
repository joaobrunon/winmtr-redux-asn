//*****************************************************************************
// FILE:            WinMTROptions.cpp
//
//
//*****************************************************************************

#include "WinMTRGlobal.h"
#include "WinMTROptions.h"
#include "WinMTRLicense.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


//*****************************************************************************
// BEGIN_MESSAGE_MAP
//
// 
//*****************************************************************************
BEGIN_MESSAGE_MAP(WinMTROptions, CDialog)
	ON_BN_CLICKED(ID_LICENSE, OnLicense)
END_MESSAGE_MAP()


//*****************************************************************************
// WinMTROptions::DoDataExchange
//
// 
//*****************************************************************************
void WinMTROptions::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT_SIZE, m_editSize);
	DDX_Control(pDX, IDC_EDIT_INTERVAL, m_editInterval);
	DDX_Control(pDX, IDC_EDIT_MAX_LRU, m_editMaxLRU);
	DDX_Control(pDX, IDC_EDIT_MAX_HOPS, m_editMaxHops);
	DDX_Control(pDX, IDC_EDIT_FIRST_TTL, m_editFirstTtl);
	DDX_Control(pDX, IDC_EDIT_TIMEOUT, m_editTimeout);
	DDX_Control(pDX, IDC_EDIT_TOS, m_editTos);
	DDX_Control(pDX, IDC_EDIT_BITPATTERN, m_editBitPattern);
	DDX_Control(pDX, IDC_EDIT_PORT, m_editPort);
	DDX_Control(pDX, IDC_EDIT_LOCALPORT, m_editLocalPort);
	DDX_Control(pDX, IDC_CHECK_DNS, m_checkDNS);
	DDX_Control(pDX, IDC_COMBO_MODE, m_comboMode);
}


//*****************************************************************************
// WinMTROptions::OnInitDialog
//
// 
//*****************************************************************************
BOOL WinMTROptions::OnInitDialog() 
{
	CDialog::OnInitDialog();
	
	char strtmp[20];
	
	sprintf(strtmp, "%.1f", interval);
	m_editInterval.SetWindowText(strtmp);
	
	sprintf(strtmp, "%d", pingsize);
	m_editSize.SetWindowText(strtmp);
	
	sprintf(strtmp, "%d", maxLRU);
	m_editMaxLRU.SetWindowText(strtmp);

	m_checkDNS.SetCheck(useDNS);

	sprintf(strtmp, "%d", maxHops);
	m_editMaxHops.SetWindowText(strtmp);

	sprintf(strtmp, "%d", firstTtl);
	m_editFirstTtl.SetWindowText(strtmp);

	sprintf(strtmp, "%d", timeoutMs);
	m_editTimeout.SetWindowText(strtmp);

	sprintf(strtmp, "%d", tos);
	m_editTos.SetWindowText(strtmp);

	sprintf(strtmp, "%d", bitPattern);
	m_editBitPattern.SetWindowText(strtmp);

	sprintf(strtmp, "%d", port);
	m_editPort.SetWindowText(strtmp);

	sprintf(strtmp, "%d", localPort);
	m_editLocalPort.SetWindowText(strtmp);

	m_comboMode.ResetContent();
	m_comboMode.AddString("ICMP");
	m_comboMode.AddString("UDP");
	m_comboMode.AddString("TCP");
	if(mode < 0 || mode > 2) mode = 0;
	m_comboMode.SetCurSel(mode);
	
	m_editInterval.SetFocus();
	return FALSE;
}


//*****************************************************************************
// WinMTROptions::OnOK
//
// 
//*****************************************************************************
void WinMTROptions::OnOK() 
{
	char tmpstr[20];
	
	useDNS = m_checkDNS.GetCheck();

	m_editInterval.GetWindowText(tmpstr, 20);
	interval = atof(tmpstr);

	m_editSize.GetWindowText(tmpstr, 20);
	pingsize = atoi(tmpstr);
	
	m_editMaxLRU.GetWindowText(tmpstr, 20);
	maxLRU = atoi(tmpstr);

	m_editMaxHops.GetWindowText(tmpstr, 20);
	maxHops = atoi(tmpstr);

	m_editFirstTtl.GetWindowText(tmpstr, 20);
	firstTtl = atoi(tmpstr);

	m_editTimeout.GetWindowText(tmpstr, 20);
	timeoutMs = atoi(tmpstr);

	m_editTos.GetWindowText(tmpstr, 20);
	tos = atoi(tmpstr);

	m_editBitPattern.GetWindowText(tmpstr, 20);
	bitPattern = atoi(tmpstr);

	mode = m_comboMode.GetCurSel();

	m_editPort.GetWindowText(tmpstr, 20);
	port = atoi(tmpstr);

	m_editLocalPort.GetWindowText(tmpstr, 20);
	localPort = atoi(tmpstr);

	CDialog::OnOK();
}

//*****************************************************************************
// WinMTROptions::OnLicense
//
// 
//*****************************************************************************
void WinMTROptions::OnLicense() 
{
	WinMTRLicense mtrlicense;
	mtrlicense.DoModal();
}
