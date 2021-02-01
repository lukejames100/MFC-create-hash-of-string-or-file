
// MFCcalMD5HASHDlg.h : 头文件
//

#pragma once
#include "afxwin.h"


// CMFCcalMD5HASHDlg 对话框
class CMFCcalMD5HASHDlg : public CDialogEx
{
// 构造
public:
	CMFCcalMD5HASHDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_MFCCALMD5HASH_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton1();
	CEdit m_text1;
	CEdit m_md5_16;
	CEdit m_md5_32;
	afx_msg void OnBnClickedButton3();
	CEdit m_file_dlg;
	afx_msg void OnBnClickedButton2();
	BOOL GetMd5(CString FileDirectory, CString &strfilemd5);
	CEdit m_edit_sha1;
	void ClearText();
	BOOL GetSha1(CString FileDirectory, CString &strfilesha1);
	BOOL GetFileData(char *pszFilePath, BYTE **ppFileData, DWORD *pdwFileDataLength);
	BOOL CalculateHash(BYTE *pData, DWORD dwDataLength, ALG_ID algHashType,BYTE **ppHashData, DWORD *pdwHashDataLength);
};
