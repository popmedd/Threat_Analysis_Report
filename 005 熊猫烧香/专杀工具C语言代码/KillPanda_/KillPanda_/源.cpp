#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Tlhelp32.h>
#pragma warning(disable : 4996)

// 3个全局变量用于最后的杀毒报告
int FixBinaryFileNumber = 0;
int FixScriptFileNumber = 0;
int DelDesktop_iniFileNumber = 0;
int SizeOfVirusFile_Bytes = 0;
char path[MAX_PATH];														// 保存病毒文件路径

																			// 结束指定进程，参数为目标进程字符串
BOOL KillPandaProcess(const char *pszProcessName)
{
	BOOL bKill = FALSE;
	HANDLE hProcess;
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)									// 如果获取进程快照失败，返回 FALSE
	{
		return bKill;
	}
	PROCESSENTRY32 pe = { 0 };
	pe.dwSize = sizeof(pe);
	BOOL bRet = Process32First(hProcessSnap, &pe);								// 获取第一个进程
	while (bRet)
	{
		if (strcmp(pe.szExeFile, pszProcessName) == 0)
		{
			bKill = TRUE;
			hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
			int ret = TerminateProcess(hProcess, 1);							// 终止进程
			if (ret)
			{
				printf("Yeah!Panda's Process is dead!\n\n");
			}
			else
			{
				printf("OMG!Panda is still alive!\n\n");
			}
			break;
		}
		bRet = Process32Next(hProcessSnap, &pe);
	}
	CloseHandle(hProcessSnap);
	return bKill;
}

// 修复注册表
void FixReg()
{
	// 删除svcshare
	char RegRun[] = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
	HKEY hKeyHKCU = NULL;
	LONG lSize = MAXBYTE;
	char cData[MAXBYTE] = { 0 };
	long lRet = RegOpenKey(HKEY_CURRENT_USER, RegRun, &hKeyHKCU);
	if (lRet == ERROR_SUCCESS)
	{
		lRet = RegQueryValueEx(hKeyHKCU, "svcshare", NULL, NULL, (unsigned char *)cData, (unsigned long *)&lSize);
		if (lRet == ERROR_SUCCESS)
		{
			if (strcmp(cData, "C:\\WINDOWS\\system32\\drivers\\spo0lsv.exe") == 0)
			{
				printf("Find virus AutorunRegInfo!\n\n");
			}
			lRet = RegDeleteValue(hKeyHKCU, "svcshare");
			if (lRet == ERROR_SUCCESS)
			{
				printf("Panda's RegItem has beed deleted!\n\n");
			}
			else
			{
				printf("Panda's RegItem is still alive or is gone!\n\n");
			}
		}
		else
		{
			printf("Reg is clear!\n\n");
		}
		RegCloseKey(hKeyHKCU);
	}
	else
	{
		printf("Open Reg failed!\n\n");
	}
	// 修复文件的隐藏显示，将CheckedValue的值设置为1
	char RegHide[] = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL";
	HKEY hKeyHKLM = NULL;
	DWORD dwFlag = 1;
	long lRetHide = RegOpenKey(HKEY_LOCAL_MACHINE, RegHide, &hKeyHKLM);
	if (lRetHide == ERROR_SUCCESS)
	{
		if (ERROR_SUCCESS == RegSetValueEx(
			hKeyHKLM,             //subkey handle  
			"CheckedValue",       //value name  
			0,                    //must be zero  
			REG_DWORD,            //value type  
			(CONST BYTE*)&dwFlag, //pointer to value data  
			4))                   //length of value data
		{
			printf("Reg fixed!\n\n");
		}
		else
		{
			printf("Can't fix RegHiddenItem or it's clear!\n\n");
		}
	}

}

// 删除指定文件
BOOL DelSPacificFile(const char * FileName)
{
	// 去除文件的隐藏、系统以及只读属性
	DWORD dwFileAttributes = GetFileAttributes(FileName);						// 获取文件属性
	dwFileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;									// &=~ 是去掉属性，| 是增加属性 ==== 这里就是去掉隐藏、系统、只读3个属性
	dwFileAttributes &= ~FILE_ATTRIBUTE_SYSTEM;
	dwFileAttributes &= ~FILE_ATTRIBUTE_READONLY;
	SetFileAttributes(FileName, dwFileAttributes);

	int delRet = DeleteFile(FileName);											// 删除文件
	if (delRet)
	{
		printf("File %s has been Deleted!\n\n", FileName);
		return TRUE;
	}
	else
	{
		printf("File %s is still alive! MayBe it has been deleted!\n\n", FileName);
		return FALSE;
	}
}

// 判断文件是否为指定二进制文件
bool IsEXE(const char* pFileName)
{
	const char* pTemp = pFileName;								// 从第一个字符开始，不断比对剩下的字符串
	while (*pTemp != 0x00)										// 注意PIF为大写
	{
		if (!strcmp(pTemp, ".exe") || !strcmp(pTemp, ".PIF") || !strcmp(pTemp, ".com") || !strcmp(pTemp, ".src"))
		{
			return true;
		}
		++pTemp;
	}
	return false;
}

// 判断文件是否为指定脚本
bool IsHTML(const char* pFileName)
{
	const char* pTemp = pFileName;
	while (*pTemp != 0x00)
	{
		if (!strcmp(pTemp, ".html") || !strcmp(pTemp, ".htm") || !strcmp(pTemp, ".asp") || !strcmp(pTemp, ".php") || !strcmp(pTemp, ".jsp") || !strcmp(pTemp, ".aspx"))
		{
			return true;
		}
		++pTemp;
	}
	return false;
}

// 根据路径名返回文件名
char *GetFilename(char *p)
{
	int x = strlen(p);
	char ch = '\\';
	char *q = strrchr(p, ch) + 1;
	return q;
}

// 修复感染二进制文件
BOOL FixBinaryFile(char* pStrFilePath)
{
	CHAR* pFilebuf = NULL;
	HANDLE hFile = CreateFile(pStrFilePath,									// 打开受感染文件
		GENERIC_READ | GENERIC_WRITE,
		FALSE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBoxA(NULL, "Open infected file failed!", "WTF!", NULL);
		return 0;
	}

	DWORD FileSize = GetFileSize(hFile, NULL);								// 获取感染后文件大小
	pFilebuf = new CHAR[FileSize]{};										// 申请个数组用来保存
	DWORD dwCount = 1;
	BOOL bRet = ReadFile(hFile, pFilebuf, FileSize, &dwCount, NULL);		// 将感染文件读入内存
	if (!bRet)																// 读取出现错误
	{
		CloseHandle(hFile);
		delete pFilebuf;
		return FALSE;
	}
	char* pFileOffset = pFilebuf + SizeOfVirusFile_Bytes;									// 被感染文件的前面，0x7531为病毒源文件大小，1ffff字节为病毒脱壳后的文件
	char *p = pStrFilePath;
	int FileNameLength = strlen(GetFilename(p));							// 获取文件名长度

	SetFilePointer(hFile, 0, 0, FILE_BEGIN);								// 0x7531是病毒的大小
	WriteFile(hFile, pFileOffset, FileSize - SizeOfVirusFile_Bytes - FileNameLength - 2, &dwCount, NULL);	// 感染标志的长度影响因子为目标文件的文件名长度
	SetEndOfFile(hFile);
	FixBinaryFileNumber++;													// 计数器统计修复个数
	CloseHandle(hFile);

	delete[] pFilebuf;
	return TRUE;
}

// 修复感染脚本文件
bool FixScriptFile(const char* pstrFilePath)
{
	CHAR* pFilebuf = NULL;
	HANDLE hFile = CreateFile(pstrFilePath,
		GENERIC_READ | GENERIC_WRITE,
		FALSE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBoxA(NULL, "Open file failed!", "WTF", NULL);
		return 0;
	}
	DWORD FileSize = GetFileSize(hFile, NULL);
	pFilebuf = new CHAR[FileSize]{};
	DWORD dwCount = 1;
	BOOL bRet = ReadFile(hFile, pFilebuf, FileSize, &dwCount, NULL);		// 文件读入内存
	if (!bRet)
	{
		CloseHandle(hFile);
		delete pFilebuf;
		return FALSE;
	}
	char* pFileOffset = pFilebuf;
	SetFilePointer(hFile, 0, 0, FILE_BEGIN);
	WriteFile(hFile, pFilebuf, FileSize - 76, &dwCount, NULL);				// 删除最后75个字节
	SetEndOfFile(hFile);
	FixScriptFileNumber++;													// 计数器统计修复个数
	CloseHandle(hFile);
	delete[] pFilebuf;
	return TRUE;
}

// 将文件读入内存并获取大小
char* GetFileBuf(char* pstrFilePath, _Out_ DWORD* FileSize)
{
	char* pFilebuf = NULL;
	//打开文件获取句柄
	HANDLE hFile = CreateFile(pstrFilePath,
		GENERIC_READ,
		FALSE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("File Open Faild!\n\n");
		return 0;
	}

	//获取文件大小
	*FileSize = GetFileSize(hFile, NULL);

	pFilebuf = new char[*FileSize]{};
	//读文件
	DWORD dwCount = 1;
	BOOL bRet = ReadFile(hFile, pFilebuf, *FileSize, &dwCount, NULL);

	if (bRet)
	{
		CloseHandle(hFile);
		return pFilebuf;
	}
	//释放资源
	CloseHandle(hFile);
	delete pFilebuf;
	return 0;

}

// 是否是被感染的二进制文件,被感染文件最后一个字节为01,向前找到00的后五个字节是WhBoy
bool IsInfectedBinaryFile(char* pstrFilePath)
{
	CHAR* pFileBuf = NULL;
	DWORD dwFileSize = 0;
	pFileBuf = GetFileBuf(pstrFilePath, &dwFileSize);
	if (pFileBuf == 0)
	{
		return false;
	}
	BYTE* pFileOffset = (BYTE*)pFileBuf;
	*pFileOffset;
	pFileOffset += (dwFileSize - 1);

	if (*pFileOffset != 0x01)									// 判断是否为0x01，不是的话就没感染
	{
		delete[] pFileBuf;
		return  false;
	}
	while (*pFileOffset != 0x00)
	{
		--pFileOffset;
	}
	pFileOffset++;
	CHAR temp[6] = { 0 };
	memcpy_s(temp, 5, pFileOffset, 5);
	if (!strcmp(temp, "WhBoy"))
	{
		delete[] pFileBuf;
		return  true;
	}
	delete[] pFileBuf;
	return  false;
}

// 是否是被感染的脚本文件
bool IsInfectedScriptFIle(char* pstrFilePath)
{
	CHAR* pFileBuf = NULL;
	DWORD dwFileSize = 0;
	pFileBuf = GetFileBuf(pstrFilePath, &dwFileSize);
	if (pFileBuf == 0)
	{
		return 0;
	}
	BYTE* pFileOffset = (BYTE*)pFileBuf;
	*pFileOffset;
	pFileOffset += (dwFileSize - 64);

	CHAR temp[32] = { 0 };
	memcpy_s(temp, 31, pFileOffset, 31);
	if (!lstrcmp(temp, "http://www.ac86.cn/66/index.htm"))
	{
		delete[] pFileBuf;
		return  TRUE;
	}
	delete[] pFileBuf;
	return  FALSE;
}

// 遍历全盘修复文件
DWORD WINAPI Delini_FixInfectedFiles(const char* lpszPath)
{
	WIN32_FIND_DATA stFindFile;
	HANDLE hFindFile;

	char szPath[MAX_PATH];
	char szFindFile[MAX_PATH];
	char szSearch[MAX_PATH];
	const char *szFilter;
	int len;
	int ret = 0;

	szFilter = "*.*";
	strcpy(szPath, lpszPath);
	len = lstrlen(szPath);
	if (szPath[len - 1] != '\\')
	{
		szPath[len] = '\\';
		szPath[len + 1] = '\0';
	}
	strcpy(szSearch, szPath);
	strcat(szSearch, szFilter);

	hFindFile = FindFirstFile(szSearch, &stFindFile);
	if (hFindFile != INVALID_HANDLE_VALUE)
	{
		do
		{
			strcpy(szFindFile, szPath);
			strcat(szFindFile, stFindFile.cFileName);

			if (stFindFile.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				if (stFindFile.cFileName[0] != '.')
				{
					Delini_FixInfectedFiles(szFindFile);
				}
			}
			else
			{
				if (!strcmp(stFindFile.cFileName, "Desktop_.ini"))						// 删除Desktop_.ini
				{

					DWORD dwFileAttributes = GetFileAttributes(szFindFile);				// 去除文件的隐藏、系统以及只读属性
					dwFileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;
					dwFileAttributes &= ~FILE_ATTRIBUTE_SYSTEM;
					dwFileAttributes &= ~FILE_ATTRIBUTE_READONLY;
					SetFileAttributes(szFindFile, dwFileAttributes);

					BOOL bRet = DeleteFile(szFindFile);
					if (bRet)
					{
						printf("\"%s\"_____deleted!\n", szFindFile);
						DelDesktop_iniFileNumber++;										// 计数器统计个数
					}
					else
					{
						printf("Deleted \"%s\" failed!\n", szFindFile);
					}
				}
				else if (IsEXE(stFindFile.cFileName))									//判断是否是二进制文件
				{
					if (IsInfectedBinaryFile(szFindFile))
					{
						// printf("%s infected!\n", szFindFile);
						if (FixBinaryFile(szFindFile))
						{
							printf("\"%s\"_____fixed!\n", szFindFile);
						}
						else
						{
							printf("Fix \"%s\" failed!\n", szFindFile);
						}
					}
					else
					{
						printf("\"%s\"_____healthy!\n\n", szFindFile);
					}
				}
				else if (IsHTML(stFindFile.cFileName))									//判断是否是脚本文件
				{
					if (IsInfectedScriptFIle(szFindFile))
					{
						// printf("%s infected!\n", szFindFile);
						if (FixScriptFile(szFindFile))
						{
							printf("\"%s\"_____fixed!\n", szFindFile);
						}
						else
						{
							printf("Fix \"%s\" failed!!!!!\n", szFindFile);
						}
					}
					else
					{
						printf("\"%s\"_____healthy!\n", szFindFile);
					}
				}
			}
			ret = FindNextFile(hFindFile, &stFindFile);
		} while (ret != 0);
	}

	FindClose(hFindFile);
	return 0;
}

// 选择病毒源文件，获取病毒源文件大小
void SelectVirusFile_GetVirusSize()
{
	// 选择Virus文件
	OPENFILENAMEA ofn;
	memset(path, 0, MAX_PATH);
	memset(&ofn, 0, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.lpstrFile = path;																	// path
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrFilter = "*.exe\0*.exe\0";
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	if (!GetOpenFileName(&ofn)) {															// 如果打开文件错误
		MessageBox(NULL, "Open file failed!", NULL, MB_OK);
		exit(0);																			// 退出所有进程
	}
	// 获取文件句柄,映射到内存
	HANDLE hFile = CreateFileA(path, GENERIC_ALL, 3u, NULL, OPEN_EXISTING, 0x80u, 0);		// path，第一个3u表示共享读写
	DWORD dwFileSize = GetFileSize(hFile, NULL);											// 获取文件大小
	SizeOfVirusFile_Bytes = dwFileSize;
}

int main()
{
	SelectVirusFile_GetVirusSize();											// 选择病毒文件，获取其大小

	FixReg();																// 修复注册表
	KillPandaProcess("spo0lsv.exe");										// 结束病毒进程

	DelSPacificFile("C:\\autorun.inf");										// 删除C盘根目录下的文件
	DelSPacificFile("C:\\setup.exe");
	DelSPacificFile("C:\\Windows\\System32\\drivers\\spo0lsv.exe");

	Delini_FixInfectedFiles("C:");											// 执行C盘感染修复
	Delini_FixInfectedFiles("D:");											// 执行D盘感染修复
																			// Delini_FixInfectedFiles("C:");										// 自行添加

	printf("\n==================YOUR PC IS CLEAR !=====================\n");
	printf("\n*********************** REPORT **************************\n");// 修复报告
	printf("The size of Virus file is %d bytes\n", SizeOfVirusFile_Bytes);
	printf("Fix binary files :%d \n", FixBinaryFileNumber);
	printf("Fix script files :%d \n", FixScriptFileNumber);
	printf("Del Desktop_.ini :%d \n", DelDesktop_iniFileNumber);
	printf("*********************** REPORT **************************\n\n");// 修复报告

	system("pause");
	return 0;
}
