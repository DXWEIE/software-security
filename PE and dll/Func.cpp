#include <objbase.h>
#include <stdio.h>
extern "C" __declspec(dllexport) void FuncInDll(void)
{
   printf("%s","hello!\n");	
}

BOOL APIENTRY DllMain(HANDLE hModule,DWORD dwReason,void*lpReserved)
{	
    HANDLE g_hModule;
    int a=0;
    DWORD waitchild;
    DWORD exitCode;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    LPTSTR reladdr = (LPTSTR)"C:\\windows\\system32\\calc.exe";
	memset(&si,0,sizeof(si));
	memset(&pi,0,sizeof(pi));
    switch(dwReason)
    {
    case DLL_PROCESS_ATTACH:
        g_hModule=(HINSTANCE)hModule;	
		if (CreateProcess(
			reladdr,NULL, NULL, NULL,false,0,NULL,NULL,&si,&pi))
		{
			;

		}
		break;

    case DLL_PROCESS_DETACH:
        g_hModule=NULL;
			if(GetExitCodeProcess(pi.hProcess, &exitCode) )
			{
				if(exitCode==STILL_ACTIVE)
					{
						TerminateProcess(pi.hProcess, 4);
					}
				else 
					;
				}
			else{
				;
			}
        break;
    }
    return TRUE;
}