
// MFCcalMD5HASH.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CMFCcalMD5HASHApp:
// �йش����ʵ�֣������ MFCcalMD5HASH.cpp
//

class CMFCcalMD5HASHApp : public CWinApp
{
public:
	CMFCcalMD5HASHApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CMFCcalMD5HASHApp theApp;