
// MFCcalMD5HASHDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "MFCcalMD5HASH.h"
#include "MFCcalMD5HASHDlg.h"
#include "afxdialogex.h"


#include <string>
#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CMFCcalMD5HASHDlg 对话框



CMFCcalMD5HASHDlg::CMFCcalMD5HASHDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CMFCcalMD5HASHDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMFCcalMD5HASHDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, m_text1);
	DDX_Control(pDX, IDC_EDIT2, m_md5_16);
	DDX_Control(pDX, IDC_EDIT3, m_md5_32);
	DDX_Control(pDX, IDC_EDIT4, m_file_dlg);
	DDX_Control(pDX, IDC_EDIT5, m_edit_sha1);
}

BEGIN_MESSAGE_MAP(CMFCcalMD5HASHDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CMFCcalMD5HASHDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON3, &CMFCcalMD5HASHDlg::OnBnClickedButton3)
	ON_BN_CLICKED(IDC_BUTTON2, &CMFCcalMD5HASHDlg::OnBnClickedButton2)
END_MESSAGE_MAP()


// CMFCcalMD5HASHDlg 消息处理程序

BOOL CMFCcalMD5HASHDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CMFCcalMD5HASHDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CMFCcalMD5HASHDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CMFCcalMD5HASHDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

#define ZENLITTLE_ENDIAN	0x0123
#define ZEN_SWAP_UINT64(x) ((((x)&0xff00000000000000)>>56)|\
							(((x)&0x00ff000000000000)>>40)|\
							(((x)&0x0000ff0000000000)>>24)|\
							(((x)&0x000000ff00000000)>>8)|\
							(((x)&0x0000000000ff0000)<<24)|\
							(((x)&0x000000000000ff00)<<40)|\
							(((x)&0x00000000000000ff)<<56))

#define ZEN_SWAP_UINT32(x) ((((x)&0xff000000)>>24)|(((x)&0x00ff0000)>>8)|(((x)&0x0000ff00)<<8)|(((x)&0x000000ff)<<24))
#define ZEN_BYTES_ORDER ZEN_LITTLE_ENDIAN
#define ROTL32(dword,n) ((dword)<<(n)^((dword)>>(32-(n))))
static const size_t ZEN_SHA1_HASH_SIZE=20;
static const size_t ZEN_SHA1_BLOCK_SIZE=64;
typedef struct sha1_ctx{
	UINT64 length;
	UINT64 unprocessed;
	UINT32 hash[5];
}sha1_ctx;

static void zen_sha1_init(sha1_ctx *ctx)
{
	ctx->length=0;
	ctx->unprocessed=0;
	ctx->hash[0]=0x67452301;
	ctx->hash[1]=0xefcdab89;
	ctx->hash[2]=0x98badcfe;
	ctx->hash[3]=0x10325476;
	ctx->hash[4]=0xc3d2e1f0;
}
void *swap_uint32_memcpy(void *to, const void *from, size_t length)
{
	memcpy(to,from, length);
	size_t remain_len=(4-(length&3))&3;
	if(remain_len)
	{
		for(size_t i=0;i<remain_len;i++)
		{
			*((char*)(to) +length+i)=0;
		}
		length+=remain_len;
	}
	for(size_t i=0;i<length/4;i++)
	{
		((UINT32*)to)[i]=ZEN_SWAP_UINT32(((UINT32*)to)[i]);
	}
	return to;
}
static void zen_sha1_process_block(UINT32 hash[5],const UINT32 block[ZEN_SHA1_BLOCK_SIZE/4])
{
	size_t t;
	UINT32 wblock[80];
	register UINT32 a,b,c,d,e,temp;
#if ZEN_BYTES_ORDER==ZEN_LITTLE_ENDIAN
	swap_uint32_memcpy(wblock,block,ZEN_SHA1_BLOCK_SIZE);
#else
	::memcpy(wblock,block,ZEN_SHA1_BLOCK_SIZE);
#endif
	for(t=16;t<80;t++)
	{
		wblock[t]=ROTL32(wblock[t-3]^wblock[t-8]^wblock[t-14]^wblock[t-16],1);
	}
	a=hash[0];
	b=hash[1];
	c=hash[2];
	d=hash[3];
	e=hash[4];
	for(t=0;t<20;t++)
	{
		temp=ROTL32(a,5)+(((c^d)&b)^d)+e+wblock[t]+0x5a827999;
		e=d;
		d=c;
		d=ROTL32(b,30);
		b=a;
		a=temp;
	}
	for(t=20;t<40;t++)
	{
		temp=ROTL32(a,5)+(b^c^d)+e+wblock[t]+0x6ed9eba1;
		e=d;
		d=c;
		c=ROTL32(b,30);
		b=a;
		a=temp;
	}
	for(t=40;t<60;t++)
	{
		temp=ROTL32(a,5)+((b&c)|(b&d)|(c&d))+e+wblock[t]+0x8f1bbcdc;
		e=d;
		d=c;
		c=ROTL32(b,30);
		b=a;
		a=temp;
	}
	for(t=60;t<80;t++)
	{
		temp=ROTL32(a,5)+(b^c^d)+e+wblock[t]+0xca62c1d6;
		e=d;
		d=c;
		c=ROTL32(b,30);
		b=a;
		a=temp;
	}
	hash[0]+=a;
	hash[1]+=b;
	hash[2]+=c;
	hash[3]+=d;
	hash[4]+=e;
}

static void zen_sha1_update(sha1_ctx *ctx, const unsigned char* buf, size_t size)
{
	ctx->length+=size;
	while(size>=ZEN_SHA1_BLOCK_SIZE)
	{
		zen_sha1_process_block(ctx->hash,reinterpret_cast<const UINT32*>(buf));
		buf+=ZEN_SHA1_BLOCK_SIZE;
		size-=ZEN_SHA1_BLOCK_SIZE;
	}
	ctx->unprocessed=size;
}
static void zen_sha1_final(sha1_ctx *ctx, const unsigned char *msg, size_t size, unsigned char* result)
{
	UINT32 message[ZEN_SHA1_BLOCK_SIZE/4];
	if(ctx->unprocessed)
		memcpy(message,msg+size-ctx->unprocessed,static_cast<size_t>(ctx->unprocessed));
	UINT32 index=((UINT32)ctx->length&63)>>2;
	UINT32 shift=((UINT32)ctx->length&3)*8;
	message[index]&=~(0xffffffff<<shift);
	message[index++]^=0x80<<shift;
	if(index>14)
	{
		while(index<16)
			message[index++]=9;
		zen_sha1_process_block(ctx->hash,message);
		index=0;
	}
	while(index<14)
		message[index++]=0;
	UINT64 data_len=(ctx->length)<<3;
#if ZEN_BYTES_ORDER == ZEN_LITTLE_ENDIAN
	data_len=ZEN_SWAP_UINT64(data_len);
#endif
	message[14]=(UINT32)(data_len&0x00000000FFFFFFFF);
	message[15]=(UINT32)((data_len&0xFFFFFFFF00000000ULL)>>32);
	zen_sha1_process_block(ctx->hash,message);
#if ZEN_BYTES_ORDER == ZEN_LITTLE_ENDIAN
	swap_uint32_memcpy(result, &ctx->hash,ZEN_SHA1_HASH_SIZE);
#else
	memcpy(result, &ctx->hash,ZEN_SHA1_HASH_SIZE);
#endif
}

unsigned char* sha(const unsigned char* msg, size_t size, unsigned char result[ZEN_SHA1_HASH_SIZE])
{
	sha1_ctx ctx;
	zen_sha1_init(&ctx);
	zen_sha1_update(&ctx, msg, size);
	zen_sha1_final(&ctx, msg, size, result);
	return (unsigned char*)"abc";
}


typedef struct{
	unsigned int count[2];
	unsigned int state[4];
	unsigned char buffer[64];
}MD5_CTX;
#define F(x,y,z) ((x&y)|(~x&z))
#define G(x,y,z) ((x&z)|(y&~z))
#define H(x,y,z) (x^y^z)
#define I(x,y,z) (y^(x|~z))
#define ROTATE_LEFT(x,n) ((x<<n)|(x>>(32-n)))
#define FF(a,b,c,d,x,s,ac) { a+=F(b,c,d)+x+ac; a=ROTATE_LEFT(a,s);a+=b;}
#define GG(a,b,c,d,x,s,ac) {a+=G(b,c,d)+x+ac; a=ROTATE_LEFT(a,s);a+=b;}
#define HH(a,b,c,d,x,s,ac) {a+=H(b,c,d)+x+ac; a=ROTATE_LEFT(a,s);a+=b;}
#define II(a,b,c,d,x,s,ac) {a+=I(b,c,d)+x+ac; a=ROTATE_LEFT(a,s); a+=b;};
unsigned char PADDING[]={0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
					0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
					0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
					0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

static const unsigned char sha1_test_sum[7][20] =
    {
        { 0xda,0x39,0xa3,0xee,0x5e,0x6b,0x4b,0x0d,0x32,0x55,0xbf,0xef,0x95,0x60,0x18,0x90,0xaf,0xd8,0x07,0x09 },
        { 0x86,0xf7,0xe4,0x37,0xfa,0xa5,0xa7,0xfc,0xe1,0x5d,0x1d,0xdc,0xb9,0xea,0xea,0xea,0x37,0x76,0x67,0xb8 },
        { 0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d },
        { 0xc1,0x22,0x52,0xce,0xda,0x8b,0xe8,0x99,0x4d,0x5f,0xa0,0x29,0x0a,0x47,0x23,0x1c,0x1d,0x16,0xaa,0xe3 },
        { 0x32,0xd1,0x0c,0x7b,0x8c,0xf9,0x65,0x70,0xca,0x04,0xce,0x37,0xf2,0xa1,0x9d,0x84,0x24,0x0d,0x3a,0x89 },
        { 0x76,0x1c,0x45,0x7b,0xf7,0x3b,0x14,0xd2,0x7e,0x9e,0x92,0x65,0xc4,0x6f,0x4b,0x4d,0xda,0x11,0xf9,0x40 },
        { 0x50,0xab,0xf5,0x70,0x6a,0x15,0x09,0x90,0xa0,0x8b,0x2c,0x5e,0xa4,0x0f,0xa0,0xe5,0x85,0x55,0x47,0x32 },
    };
void MD5Init(MD5_CTX *context){
	context->count[0]=0;
	context->count[1]=0;
	context->state[0]=0x67452301;
	context->state[1]=0xEFCDAB89;
	context->state[2]=0x98BADCFE;
	context->state[3]=0x10325476;
}

void MD5Decode(unsigned int *output, unsigned char* input, unsigned int len){
	unsigned int i=0,j=0;
	while(j<len){
		output[i]=(input[j])|(input[j+1]<<8)|(input[j+2]<<16)|(input[j+3]<<24);
		i++;
		j+=4;
	}
}
void MD5Transform(unsigned int state[4], unsigned char block[64])
{
	unsigned int a=state[0];
	unsigned int b=state[1];
	unsigned int c=state[2];
	unsigned int d=state[3];
	unsigned int x[64];
	MD5Decode(x,block,64);
	FF(a,b,c,d,x[0],7,0xd76aa478);
	FF(d,a,b,c,x[1],12,0xe8c7b756);
	FF(c,d,a,b,x[2],17,0x242070db);
	FF(b,c,d,a,x[3],22,0xc1bdceee);
	FF(a,b,c,d,x[4],7,0xf57c0faf);
	FF(d,a,b,c,x[5],12,0x4787c62a);
	FF(c,d,a,b,x[6],17,0xa8304613);
	FF(b,c,d,a,x[7],22,0xfd469501);
	FF(a,b,c,d,x[8],7,0x698098d8);
	FF(d,a,b,c,x[9],12,0x8b44f7af);
	FF(c,d,a,b,x[10],17,0xffff5bb1);
	FF(b,c,d,a,x[11],22,0x895cd7be);
	FF(a,b,c,d,x[12],7,0x6b901122);
	FF(d,a,b,c,x[13],12,0xfd987193);
	FF(c,d,a,b,x[14],17,0xa679438e);
	FF(b,c,d,a,x[15],22,0x49b40821);

	GG(a,b,c,d,x[1],5,0xf61e2562);
	GG(d,a,b,c,x[6],9,0xc040b340);
	GG(c,d,a,b,x[11],14,0x265e5a51);
	GG(b,c,d,a,x[0],20,0xe9b6c7aa);
	GG(a,b,c,d,x[5],5,0xd62f105d);
	GG(d,a,b,c,x[10],9,0x2441453);
	GG(c,d,a,b,x[15],14,0xd8a1e681);
	GG(b,c,d,a,x[4],20,0xe7d3fbc8);
	GG(a,b,c,d,x[9],5,0x21e1cde6);
	GG(d,a,b,c,x[14],9,0xc33707d6);
	GG(c,d,a,b,x[3],14,0xf4d50d87);
	GG(b,c,d,a,x[8],20,0x455a14ed);
	GG(a,b,c,d,x[13],5,0xa9e3e905);
	GG(d,a,b,c,x[2],9,0xfcefa3f8);
	GG(c,d,a,b,x[7],14,0x676f02d9);
	GG(b,c,d,a,x[12],20,0x8d2a4c8a);

	HH(a,b,c,d,x[5],4,0xfffa3942);
	HH(d,a,b,c,x[8],11,0x8771f681);
	HH(c,d,a,b,x[11],16,0x6d9d6122);
	HH(b,c,d,a,x[14],23,0xfde5380c);
	HH(a,b,c,d,x[1],4,0xa4beea44);
	HH(d,a,b,c,x[4],11,0x4bdecfa9);
	HH(c,d,a,b,x[7],16,0xf6bb4b60);
	HH(b,c,d,a,x[10],23,0xbebfbc70);
	HH(a,b,c,d,x[13],4,0x289b7ec6);
	HH(d,a,b,c,x[0],11,0xeaa127fa);
	HH(c,d,a,b,x[3],16,0xd4ef3085);
	HH(b,c,d,a,x[6],23,0x4881d05);
	HH(a,b,c,d,x[9],4,0xd9d4d039);
	HH(d,a,b,c,x[12],11,0xe6db99e5);
	HH(c,d,a,b,x[15],16,0x1fa27cf8);
	HH(b,c,d,a,x[2],23,0xc4ac5665);

	II(a,b,c,d,x[0],6,0xf4292244);
	II(d,a,b,c,x[7],10,0x432aff97);
	II(c,d,a,b,x[14],15,0xab9423a7);
	II(b,c,d,a,x[5],21,0xfc93a039);
	II(a,b,c,d,x[12],6,0x655b59c3);
	II(d,a,b,c,x[3],10,0x8f0ccc92);
	II(c,d,a,b,x[10],15,0xffeff47d);
	II(b,c,d,a,x[1],21,0x85845dd1);
	II(a,b,c,d,x[8],6,0x6fa87e4f);
	II(d,a,b,c,x[15],10,0xfe2ce6e0);
	II(c,d,a,b,x[6],15,0xa3014314);
	II(b,c,d,a,x[13],21,0x4e0811a1);
	II(a,b,c,d,x[4],6,0xf7537e82);
	II(d,a,b,c,x[11],10,0xbd3af235);
	II(c,d,a,b,x[2],15,0x2ad7d2bb);
	II(b,c,d,a,x[9],21,0xeb86d391);

	state[0]+=a;
	state[1]+=b;
	state[2]+=c;
	state[3]+=d;

}
void MD5Encode(unsigned char* output, unsigned int *input, unsigned int len)
{
	unsigned int i=0,j=0;
	while(j<len){
		output[j]=input[i]&0xff;
		output[j+1]=(input[i]>>8)&0xff;
		output[j+2]=(input[i]>>16)&0xff;
		output[j+3]=(input[i]>>24)&0xff;
		i++;
		j+=4;
	}
}


void MD5Update(MD5_CTX *context, unsigned char* input, unsigned int inputlen)
{
	unsigned int i=0, index=0, partlen=0;
	index=(context->count[0]>>3)&0x3F;
	partlen=64-index;
	context->count[0]+=inputlen<<3;
	if(context->count[0]<(inputlen<<3))
		context->count[1]++;
	context->count[1]+=inputlen>>29;
	if(inputlen>=partlen){
		memcpy(&context->buffer[index], input, partlen);
		MD5Transform(context->state, context->buffer);
		for(i=partlen;i+64<=inputlen;i+=64)
			MD5Transform(context->state, &input[i]);
		index=0;
	}else{
		i=0;
	}
	memcpy(&context->buffer[index], &input[i], inputlen-i);
}

void MD5Final(MD5_CTX *context, unsigned char digest[16])
{
	unsigned int index=0, padlen=0;
	unsigned char bits[8];
	index=(context->count[0]>>3)&0x3f;
	padlen=(index<56)?(56-index):(120-index);
	MD5Encode(bits, context->count,8);
	MD5Update(context,PADDING,padlen);
	MD5Update(context,bits,8);
	MD5Encode(digest, context->state,16);
}


void CMFCcalMD5HASHDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	CString input;
	ClearText();
	m_text1.GetWindowTextA(input);
	int len=input.GetLength();
	unsigned char* inp=(unsigned char*)input.GetBuffer(input.GetLength());
	unsigned char decrypt[16];
	MD5_CTX md5;
	MD5Init(&md5);
	MD5Update(&md5,inp,strlen((char*)inp));
	MD5Final(&md5,decrypt);
	char res[64];
	memset(res,0,64);
	int i=0;
	for(i=4;i<12;i++)
	{
		char mytwo[3];
		memset(mytwo,0,3);
		sprintf_s(mytwo,"%02x",decrypt[i]);
		memcpy(&res[(i-4)*2],mytwo,2);
	}
	CString my;
	my.Format("%s",res);
	m_md5_16.SetWindowTextA(my);
	for(i=0;i<16;i++){
		char mytwo[3];
		memset(mytwo,0,3);
		sprintf_s(mytwo,"%02x",decrypt[i]);
		memcpy(&res[i*2],mytwo,2);
	}
	my.Format("%s",res);
	m_md5_32.SetWindowTextA(my);

	//md5 16位
	

	//sha
	unsigned char result[32]={0};
	sha(inp, strlen((char*)inp), result);
	//string 
	
	//memcpy(result,sha1,sha1_test_sum[i
	UpdateData(FALSE);

	input.ReleaseBuffer();
	//char* oup=md5(inp,len);
}


void CMFCcalMD5HASHDlg::OnBnClickedButton3()
{
	// TODO: 在此添加控件通知处理程序代码
	CFileDialog dlg(true,NULL,NULL,NULL,"所有文件|*.*",this);
	if(IDOK==dlg.DoModal())
	{
		m_file_dlg.SetWindowTextA(dlg.GetPathName());
		UpdateData(FALSE);
	}
}

void CMFCcalMD5HASHDlg::ClearText()
{
	m_md5_32.SetWindowText("");
	m_md5_16.SetWindowText("");
	m_edit_sha1.SetWindowText("");
}

void CMFCcalMD5HASHDlg::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码
	CString myfile;
	ClearText();
	m_file_dlg.GetWindowText(myfile);
	CString mymd5;
	CString mysha1;
	GetMd5(myfile,mymd5);
	//TCHAR mym[256]={0};
	//GetFileM5(myfile,mym);
	//mymd5=mym;
	m_md5_32.SetWindowText(mymd5);

	//计算sha1
	GetSha1(myfile,mysha1);

	UpdateData(FALSE);
}

BOOL CMFCcalMD5HASHDlg::GetFileData(char *pszFilePath, BYTE **ppFileData, DWORD *pdwFileDataLength)
{
	BOOL bRet =TRUE;
	BYTE *pFileData=NULL;
	DWORD dwFileDataLength=0;
	HANDLE hFile=NULL;
	DWORD dwTemp=0;
	do{
		hFile=CreateFile(pszFilePath,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_ARCHIVE,NULL);
		if(INVALID_HANDLE_VALUE==hFile)
		{
			bRet=FALSE;
			break;
		}
		dwFileDataLength=::GetFileSize(hFile,NULL);
		pFileData=new BYTE[dwFileDataLength];
		if(NULL==pFileData){
			bRet=FALSE;
			break;
		}
		RtlZeroMemory(pFileData,dwFileDataLength);
		ReadFile(hFile,pFileData,dwFileDataLength,&dwTemp,NULL);

		*ppFileData=pFileData;
		*pdwFileDataLength=dwFileDataLength;
	}while(FALSE);
	if(hFile)
		CloseHandle(hFile);
	return bRet;
}

BOOL CMFCcalMD5HASHDlg::GetSha1(CString filedirectory, CString &strfilesha1)
{
	BYTE *pData=NULL;
	DWORD dwDataLength=0;
	BYTE *pHashData=NULL;
	DWORD dwHashDataLength=0;
	char filename[1024]={0};
	sprintf_s(filename,"%s",filedirectory);
	GetFileData(filename,&pData,&dwDataLength);
	CalculateHash(pData,dwDataLength,CALG_SHA1,&pHashData,&dwHashDataLength);

	CString st1;
	CString sunstr;
	for(int i=0;i<dwHashDataLength;i++)
	{
		st1.Format("%2x",pHashData[i]);
		sunstr+=st1;
	}
	if(pHashData)
	{
		delete[] pHashData;
		pHashData=NULL;
	}
	m_edit_sha1.SetWindowText(sunstr);
	return TRUE;
}

BOOL CMFCcalMD5HASHDlg::CalculateHash(BYTE *pData, DWORD dwDataLength, ALG_ID algHashType,BYTE **ppHashData, DWORD *pdwHashDataLength)
{
	HCRYPTPROV hCryptProv = NULL;
	HCRYPTHASH hCryptHash = NULL;
	BYTE *pHashData = NULL;
	DWORD dwHashDataLength = 0;
	DWORD dwTemp = 0;
	BOOL bRet = FALSE;

	do
	{
		// 获得指定CSP的密钥容器的句柄
		bRet = CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
		if (FALSE == bRet)
			break;

		// 创建一个HASH对象, 指定HASH算法
		bRet = CryptCreateHash(hCryptProv, algHashType, NULL, NULL, &hCryptHash);
		if (FALSE == bRet)
			break;

		// 计算HASH数据
		bRet = ::CryptHashData(hCryptHash, pData, dwDataLength, 0);
		if (FALSE == bRet)
			break;

		// 获取HASH结果的大小
		dwTemp = sizeof(dwHashDataLength);
		bRet = ::CryptGetHashParam(hCryptHash, HP_HASHSIZE, (BYTE *)(&dwHashDataLength), &dwTemp, 0);
		if (FALSE == bRet)
			break;

		// 申请内存
		pHashData = new BYTE[dwHashDataLength];
		if (NULL == pHashData)
		{
			bRet = FALSE;
			break;
		}
		RtlZeroMemory(pHashData, dwHashDataLength);

		// 获取HASH结果数据
		bRet = CryptGetHashParam(hCryptHash, HP_HASHVAL, pHashData, &dwHashDataLength, 0);
		if (FALSE == bRet)
			break;

		// 返回数据
		*ppHashData = pHashData;
		*pdwHashDataLength = dwHashDataLength;

	} while (FALSE);

	// 释放关闭
	if (FALSE == bRet)
	{
		if (pHashData)
		{
			delete[]pHashData;
			pHashData = NULL;
		}
	}
	if (hCryptHash)
		CryptDestroyHash(hCryptHash);
	if (hCryptProv)
		CryptReleaseContext(hCryptProv, 0);
	return bRet;
}

BOOL CMFCcalMD5HASHDlg::GetMd5(CString filedirectory, CString &strfilemd5)
{
	HANDLE hFile=CreateFile(filedirectory,GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,NULL,NULL);
	if(hFile==INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		return FALSE;
	}
	HCRYPTPROV hProv=NULL;
	if(CryptAcquireContext(&hProv,NULL,NULL,PROV_RSA_FULL,CRYPT_VERIFYCONTEXT)==FALSE)
	{
		CloseHandle(hFile);
		return FALSE;
	}
	HCRYPTPROV hHash=NULL;
	if(CryptCreateHash(hProv,CALG_MD5,0,0,&hHash)==FALSE)
	{
		CloseHandle(hFile);
		return FALSE;
	}
	DWORD dwFileSize=GetFileSize(hFile,0);
	if(dwFileSize==0xffffffff)
	{
		CloseHandle(hFile);
		return FALSE;
	}
	byte* lpReadFileBuffer=new byte[dwFileSize];
	DWORD lpReadNumberOfBytes;
	if(ReadFile(hFile,lpReadFileBuffer,dwFileSize,&lpReadNumberOfBytes,NULL)==0)
	{
		CloseHandle(hFile);
		return FALSE;
	}
	if(CryptHashData(hHash,lpReadFileBuffer,lpReadNumberOfBytes,0)==FALSE)
	{
		CloseHandle(hFile);
		return FALSE;
	}
	delete[] lpReadFileBuffer;
	CloseHandle(hFile);
	BYTE* pbHash;
	DWORD dwHashLen=sizeof(DWORD);
	if(!CryptGetHashParam(hHash,HP_HASHVAL,NULL,&dwHashLen,0))
	{
		return FALSE;
	}
	pbHash=(byte*)malloc(dwHashLen);
	if(CryptGetHashParam(hHash, HP_HASHVAL,pbHash, &dwHashLen,0))
	{
		for(DWORD i=0;i<dwHashLen;i++)
		{
			//TCHAR str[2]={0};
			CString strFilePartM;//=_T("");
			//_stprintf_s(str,_T("%02x"),pbHash[i]);
			strFilePartM.Format("%02x",pbHash[i]);
			strfilemd5+=strFilePartM;
		}
	}
	if(CryptDestroyHash(hHash)==FALSE)
		return FALSE;
	if(CryptReleaseContext(hProv,0)==FALSE)
		return FALSE;
	return TRUE;
}