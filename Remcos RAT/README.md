



# EXECUTIVE SUMMARY - FINDINGS




### IOCs:
- Malware SHA256:  
0d97708b73548a54a6a9995f484e942e3d72050e7a02d71ab16ed776e6300410  
- Binary:  
rmclient.exe 
<br>
- Used port: 23101  
- Domains:  
sun.drillmmcsnk[.]eu:23101  
rem.pushswroller[.]eu:23101  
firewarzone.ydns[.]eu:23101  
- IP: 45.80.158[.]30  
<br>
- Registry:  
"Software\Rmcghghyrtssxr-7RL1P2\"
<br>

- Other indicators:  
http://geoplugin[.]net/json.gp (Not malicious per se, but likely used to get infected hosts Geolocation).  
BreakingSecurity[.]net (That's the redteam that created the tool thats now used by Malicious actors)



### TOOLS & BEHAVIOUR:
- fsutils.exe, svchost.exe and rmclient.exe (Got external info that they are used for Masquerading with process injection of the Watchdog, according to Elastic Security)
- Clipboard Keylogger via WinAPI (addr USER32.DLL::GetClipboardData and "keylogger 00465b24 s_Offline_Keylogger_Started_00465b24 ds "Offline Keylogger Started"")
- UAC bypass (reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f)
- Clears various browser cookies and logins, likely also can upload browser history and passwords
- Registry Run keys ("Software\\Microsoft\\Windows\\CurrentVersion\\Run\\")
- Local recon, reads: C:\Windows\Prefetch\0D97708B73548A54A6A9995F484E9-E7B7F9F6.pf
- Shlwapi.dll likely used to query, set and delete keys in registry.
- gdiplus.dll (Might be used to access data in a online picture to be loaded into for example memory)
- ieinstal.exe (Process injection)
- ielowutil.exe (Process injection)
- Encryption: AES, XOR, RC4 KSA & PRGA, OpenSSL ECDSA, HMAC, SHA256, generates random numbers via WinAPI CryptGenRandom @ 0x432962
- Also the malware has the ability to create suspended processes & Process Hollowing.



## Verifying work by external sources - Could not find or connect theses, but got info from external sources after done:
- Audio recording capabilities according to Elastic
- Knew these tools were used but not how: fsutils.exe, svchost.exe and rmclient.exe (Got external info that they are used for Masquerading with process injection of the Watchdog, according to Elastic Security Labs)
- Wscript Shell Run cmd  is according to Elastic used to kill the Watchdog and restart Remcos binary (004663b0 u"CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"")	
- Obviously there are more of the expected functions from a RAT present, not covered here, but pointed out by Elastic and Researchers (Like: Process termination/suspend/resume capabilities, execute shell commands, download DLLs and execute programs).
- See further info revealed by the tool Capa for read longer down.




<br>
<br>

# ANALYSIS PROCESS IN CHRONOLOGICAL ORDER OF HOW ANALYSIS WAS DONE



### INDEX LIST


PRE-ANALYSIS  

0. Check if 32- or 64-bit with PE Studio and CFF Explorer

INITIAL STATIC ANANLYSIS IN GHIDRA  
1. Disassembly Static - Step one was following interesting WinAPI calls 
2. Step two involved following suspicious strings
3. Function Call Graph - Continuing the trail from Clipboard investigation 
4. Function Graph - Continuing the trail from Clipboard investigation
5. "CALL" - Looking for more calls
6. Debugger Dynamic Analysis - x32dbg Debugger
7. Executing malware and observing registry changes

DETAILS OF STATIC ANANLYSIS IN GHIDRA  

8. C2 and Proxy tunneling

DEPLOYMENT OF EXTRA TOOLS AS BACKUP IF I MISSED SOMETHING IMPORTANT  

9. CAPA for extra checks

DECRYPTING REMOCOS RAT CONFIG FILE  

10. Using Capa findings regarding RC4 - Decrypting config file with CFF Explorer VIII & Cyberchef 



<br>

### TOOLS & SOURCES USED:


#### Tools:  
- PE Studio  
- CFF Explorer VIII  
- Ghidra  
- x32dbg Debugger  
- Regshot  
- Capa  
- Cyberchef  

#### Source used for second opinion to verify analysis:  
- Elastic Security Labs  

<br>
<br>

# PRE-ANALYSIS



### 0. Check if 32- or 64-bit with PE Studio and CFF Explorer

- It's 32bit.

<br>
<br>


# INITIAL STATIC ANANLYSIS IN GHIDRA


### 1. GHIDRA Disassembly Static - Step one was following interesting WinAPI calls 

#### FINDINGS SUMMARY:  
- Create process CMD that launched reg.exe to turn off UAC by modifying the EnableLUA regkey.

#### HOW:  
- Via Window -->  Symbol References --> Press: Configure symbol references --> Tick only these boxes:  
Source: Imported
Symbol Types: Function Labels 

#### PROOF:  
>CreateProcessA("C:\\Windows\\System32\\cmd.exe",  
&nbsp;                "/k %windir%\\System32\\reg.exe ADD  <br> &nbsp; HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f" <br> &nbsp;
                 ,(LPSECURITY_ATTRIBUTES)0x0,(LPSECURITY_ATTRIBUTES)0x0,0, <br> &nbsp; CREATE_NO_WINDOW, <br> &nbsp;
                 (LPVOID)0x0,(LPCSTR)0x0,&local_5c,&local_14);  <br> &nbsp;
  CloseHandle(local_14.hProcess);  <br> &nbsp;
  CloseHandle(local_14.hThread);  
  return;


<br>

### 2. Step two involved following suspicious strings

#### FINDINGS SUMMARY:  
- Clipboard seems to be used, and warrants further investigation

#### HOW:  
- Window --> Defined Strings

#### PROOF:  
>00465d7c	[Ctrl+V]  
[Text pasted from clipboard]  
&nbsp;	"[Ctrl+V]\r\n[Text pasted from clipboard]\r\n"	ds


<br>

### 3. Function Call Graph - Continuing the trail from Clipboard investigation 

#### FINDINGS SUMMARY: 
- Collection of Clipboard data 

#### HOW:
- In Listing view the findings from Defined strings should be highlighted, and by right clicking and choosing:  
Referenses --> Show references to address  
- Then (because no immediate clear indication found) to see relationships; use Window --> Function Call Graph  

#### PROOF:
- OpenClipboard, GetClipboardData, CloseClipboard

<br>

### 4. Function Graph - Continuing the trail from Clipboard investigation

#### FINDINGS SUMMARY: 
- Continuation of validating clipboard data is accessed and obtained if exist.

#### HOW:
- After graph view, in Listings view press "g" and fill in the functions name (the parent to the clipboard calls; FUN_0040ae1e)
- Then to see the functions individual code blocks; go to Window --> Function Graph

#### PROOF:
- Here we see Jump (JZ) to 0 if clipboard fails, otherwise if not 0 then access to clipboard succeeded and no jump is done. Instead new API calls are made to get the clipboard data.

<br>

### 5. "CALL" - Looking for more calls

#### FINDINGS SUMMARY: 
- Revealed several calls to investigate

#### HOW:
- Window --> Script Manager --> Create New Script --> Python --> Add below script:  
<br>
>fn = getFunctionAt(currentAddress)  
i = getInstructionAt(currentAddress)  
while getFunctionContaining(i.getAddress()) == fn:  
&nbsp;	nem = i.getMnemonicString()  
&nbsp;	if nem == "CALL":  
&nbsp;&nbsp;&nbsp;&nbsp;		target_address = i.getOpObjects(0)[0]  
&nbsp;&nbsp;&nbsp;&nbsp;		print(nem + " " + str(getSymbolAt(target_address)))  
&nbsp;	i = i.getNext()  


<br>

### 6. Debugger Dynamic Analysis - x32dbg Debugger

#### FINDINGS SUMMARY: 
- Found several IOCs domains:  
Used port: 23101  
Domain: sun.drillmmcsnk[.]eu:23101  
Domain: rem.pushswroller[.]eu:23101  
Domain: firewarzone.ydns[.]eu:23101  

#### HOW:
- Running malware in x32dbg, looking at stack and data being pushed onto stack, the bottom right window of x32dbg.

#### PROOF:
- Rawdata:  
>0019FC54  004742F8  0d97708b73548a54a6a9995f484e942e3d72050e7a02d71ab16ed776e6300410.&"Software\\Rmcghghyrtssxr-7RL1P2\\"
0019FC58  00000000  
0019FC5C  00000000  
0019FC60  006D0130  "Software\\Rmcghghyrtssxr-7RL1P2\\"
0019FC64  0019FF64  
0019FC68  76901830  kernelbase._invalid_parameter+110
0019FC6C  9AF351CC  
0019FC70  006D14A0  &"rem.pushswroller[.]eu:23101:1"


- Seems to be a regkey:  
>"Software\\Rmcghghyrtssxr-7RL1P2\\"
<br>
02CAE948  00775B30  "S On  | sun.drillmmcsnk[.]eu:23101"  
02CAE948  00775B30  "S On  | rem.pushswroller[.]eu:23101"  
02CAE948  00775B30  "S On  | firewarzone.ydns[.]eu:23101"  
<br>
007758E0 "Connecting  | TLS On  | rem.pushswroller[.]eu:23101"  
02CAFBB0  007758E0  "Connecting  | TLS On  | firewarzone.ydns[.]eu:23101"  
<br>

- Looking it up externally on Virustotal confirms malicious IOCs:  
IP: 45.80.158[.]30  
hostname: firewarzone.ydns[.]eu  
reverse lookup: rem.pushswroller[.]eu  


### 7. Executing malware and observing registry changes

#### FINDINGS SUMMARY: 
- Found interesting regkey changes, whereas one was a regkey holding the Remcos binary itself with configuration settings.

#### HOW:
- Regshot before execution and after for comparison.


#### PROOF:  

- Regshot compared registry before and after execution:  
Keys added: 17  
Values added: 52  
Values modified: 86  
Folders added: 0  
Folders attributes changed: 0  
Files added: 0  
Files [attributes?] modified: 0  

- Interesting registry keys added:  
RegCreateKey HKCU\Software\Rmcghghyrtssxr-7RL1P2\  
<br> 
Operation: RegSetValue  
Path: HKCU\Software\Rmcghghyrtssxr-7RL1P2\licence  
Result: SUCCESS  
Type: REG_SZ  
Data: 8FBF0123A853BB276AFD9A03F573AE61  
<br> 
Operation: RegSetValue  
Path: HKCU\Software\Rmcghghyrtssxr-7RL1P2\exepath  
Result: SUCCESS  
Type: REG_BINARY  
Data: CA 01 84 77 E5 32 4B 76 C6 25 47 BD 5D 94 68 2B.......(see further below for full data)  

- The data in the registry is a Remcos binary that contains the configuration settings for the RAT:  
>[HKEY_CURRENT_USER\Software\Rmcghghyrtssxr-7RL1P2]  
"exepath"=hex:ca,01,84,77,e5,32,4b,76,c6,25,47,bd,5d,94,68,2b,71,a4,a8,5a,18,\  
&nbsp;  f0,c9,9f,a9,a8,ac,39,d7,50,68,7b,8b,e3,d0,bd,45,c8,44,72,73,d3,cf,9b,f6,8d,\  
&nbsp;  68,b4,8a,3c,67,46,8c,d6,20,93,6d,71,a1,3d,72,f5,8d,fa,1e,da,e3,a6,d5,f3,5e,\  
&nbsp;  70,c7,f4,d4,74,57,f7,c0,22,13,64,60,16,ec,1b,9d,29,e0,d6,90,1c,47,6a,21,8a,\  
&nbsp;  a1,e4,f7,0a,8e,21,c0,be,61,da,7f,3d,5c,a1,5b,62,b3,aa,15,29,1b,c1,fd,61,25,\  
&nbsp;  36,d5,30,d5,5b,aa,74,83,2a,eb,13,17,be,91,0f,4c,46,06,27,30,a7,0d,f3,3a,76,\  
&nbsp;  dc,a5,0d,ab,3e,63,6a,2d,a6,25,8a,74,b8,18,14,35,5b,15,4f,e5,8c,7f,8c,19,c0,\  
&nbsp;  c1,bf,d5,cc,6a,e5,0f,b6,52,af,04,91,43,8d,9a,13,f4,e3,57,8a,67,b6,b6,de,0e,\  
&nbsp;  95,9d,a6,d6,a5,a5,6f,66,d8,98,21,82,f1,41,8e,37,b3,80,73,24,c0,58,71,34,e6,\  
&nbsp;  12,ef,46,2f,3b,f3,bc,53,95,c1,fa,0e,87,14,5e,ba,f6,04,34,03,d5,30,bf,83,be,\  
&nbsp;  7e,cd,a8,f0,ae,e1,4d,15,73,80,bf,89,36,b6,c5,d2,fb,4f,72,07,3d,1e  
"licence"="8FBF0123A853BB276AFD9A03F573AE61"  
"time"=dword:676ab9eb  



- Containing clipboard data with files starting with the text: "Offline Keylogger Started":  
C:\ProgramData\remcos\logs.dat  
and  
C:\Users\user\AppData\Local\VirtualStore\ProgramData\remcos\logs.dat  







# DETAILS OF STATIC ANANLYSIS IN GHIDRA




### 8. C2 and Proxy tunneling:
 C2 and Proxy tunneling | b | c 
---|---|---
WS2_32.DLL::recv (receive data on socket)                   |0040459f   |CALL dword ptr [->WS2_32.DLL::recv]
ThreadLocalStoragePointer                                   |00405042   |MOV EAX,FS:[offset ThreadLocalStoragePointer]
Cmd (ReverseShell)                                          |004050f5   |MOV EDX,s_cmd.exe_00465558
SystemDrive                                                 |00405109   |PUSH s_SystemDrive_00465560
KERNEL32.DLL::CreatePipe (ReverseShell)                     |0040515e   |CALL ESI=>KERNEL32.DLL::CreatePipe
KERNEL32.DLL::CreateProcessA (ReverseShell)                 |004051e7   |CALL dword ptr [->KERNEL32.DLL::CreateProcessA
KERNEL32.DLL::PeekNamedPipe (ReverseShell)                  |00405264   |CALL dword ptr [->KERNEL32.DLL::PeekNamedPipe]
KERNEL32.DLL::ReadFile (ReverseShell)                       |00405291   |CALL dword ptr [->KERNEL32.DLL::ReadFile]
KERNEL32.DLL::WriteFile (file-transfer & file-system write)	|0040538e   |CALL dword ptr [->KERNEL32.DLL::WriteFile]
URLMON.DLL::URLDownloadToFileW                              |00406318   |CALL dword ptr [->URLMON.DLL::URLDownloadToFileW]



 Interesting process creations | b | c 
---|---|---
LPSTR lpCommandLine for CreateProcessA      |004069f6   |PUSH s_/k_%windir%\System32\reg.exe_ADD_00465910
LPCSTR lpApplicationName for CreateProcessA |004069fb   |PUSH s_C:\Windows\System32\cmd.exe_00465994
call 2 createProc w Push instruct           |00406a00   |CALL dword ptr [->KERNEL32.DLL::CreateProcessA]
WS2_32.DLL::gethostbyname (Resolve DNS)     |004137af   |CALL dword ptr [->WS2_32.DLL::gethostbyname]
URLMON.DLL::URLDownloadToFileW              |004157a7   |CALL dword ptr [->URLMON.DLL::URLDownloadToFileW]



 System Shutdown/Reboot | b | c 
---|---|---
........................                |0041595b   |CALL dword ptr [->USER32.DLL::ExitWindowsEx]
LPCSTR lpProcName for GetProcAddress    |00415966   |PUSH s_SetSuspendState_0046b9b0
LPCSTR lpLibFileName for LoadLibraryA   |0041596b   |PUSH s_PowrProf.dll_0046b9c0



 Then Screen capture/recording (and audio recording according to Elastic) | b | c 
---|---|---  
LPCSTR pwszDriver for CreateDCA |00417fb2	|PUSH s_DISPLAY_0046bac8  
...								|00417fb9	|CALL dword ptr [->GDI32.DLL::CreateDCA]
...								|00417fc4	|CALL dword ptr [->GDI32.DLL::CreateCompatibleDC]
...								|00418045	|CALL dword ptr [->GDI32.DLL::CreateCompatibleBitmap]
...								|00418144	|CALL dword ptr [->GDI32.DLL::BitBlt]
...								|0041826b	|CALL dword ptr [->GDI32.DLL::GetDIBits]



 Continuation of C2 stuff | b | c 
---|---|--- 
WININET.DLL::InternetOpenW (HTTP request, connect to URL)	|0041a53e	|CALL dword ptr [->WININET.DLL::InternetOpenW]
WS2_32.DLL::send (send data on socket) (~geolocation recon)	|0041a54e	|PUSH u_http://geoplugin.net/json.gp_0046b95c
WININET.DLL::InternetOpenUrlW (Read Data from Internet)		|0041a554	|CALL dword ptr [->WININET.DLL::InternetOpenUrlW]
WININET.DLL::InternetReadFile (read data from Internet)		|0041a56d	|CALL dword ptr [->WININET.DLL::InternetReadFile]
URLMON.DLL::URLOpenBlockingStream (Download URL)		    |0041abd1	|CALL dword ptr [->URLMON.DLL::URLOpenBlockingStreamW]


 Other indicators at other places in code | b | c 
---|---|--- 
WS2_32.DLL::send (send data on socket)				|00426118	|CALL dword ptr [->WS2_32.DLL::send]
wininet.dll							                |00457428	|PTR_InternetOpenUrlW_00457428	addr WININET.DLL::InternetOpenUrlW
http shell open cmd						            |0046bc94	|u_http\shell\open\command_0046bc94	unicode u"http\\shell\\open\\command"


Malware checks if it's being debugged | b | c 
---|---|--- 
IsDebuggerPresent						    |0043a755	|CALL dword ptr [->KERNEL32.DLL::IsDebuggerPresent]


 Keylogger - Clipboard usage | b | c 
---|---|--- 
Clipboard	GetClipboardData				|0045738c	|PTR_GetClipboardData_0045738c	addr USER32.DLL::GetClipboardData
Clipboard	CloseClipboard					|004573a4	|PTR_CloseClipboard_004573a4	addr USER32.DLL::CloseClipboard
Clipboard	OpenClipboard					|004573a8	|PTR_OpenClipboard_004573a8	addr USER32.DLL::OpenClipboard
keylogger							        |00465b24	|s_Offline_Keylogger_Started_00465b24	ds "Offline Keylogger Started"



 Likely webcamera access capabilities | b | c 
---|---|--- 
OpenCamera							        |0045b0d4	|s_operator_""_0045b0d4	ds "operator \"\" "



 Privilege Escalation Capabilities | b | c 
---|---|--- 
Elevate to Admin						    |004657d0	|u_Elevation:Administrator!new:_004657d0	unicode u"Elevation:Administrator!new:"



 UAC bypass | b | c 
---|---|--- 
reg								|00465910	|s_/k_%windir%\System32\reg.exe_ADD_00465910	ds "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f"
cmd								|00465994	|s_C:\Windows\System32\cmd.exe_00465994	ds "C:\\Windows\\System32\\cmd.exe"



 Persistance | b | c 
---|---|--- 
Shell folders							                    |00466010	|Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders	
Runkey								                        |004660f0	|u_Software\Microsoft\Windows\Curre_004660f0	unicode u"Software\\Microsoft\\Windows\\CurrentVersion\\Run
Shell Run cmd (Elastic: used to restart Remcos binary)		|004663b0	|u_CreateObject("WScript.Shell").Ru_004663b0	unicode u"CreateObject(\"WScript.Shell\").Run \"cmd /c \"\""


 Initialization & Activation | b | c 
---|---|--- 
txt								                        |0046660c	|s_license_code.txt_0046660c	ds "license_code.txt"
Remcos initialized						                |00466644	|s_Remcos_Agent_initialized_00466644	ds "Remcos Agent initialized"
Watchdog							                    |0046b718	|s_Watchdog_module_activated_0046b718	ds "Watchdog module activated"
Process Injection for Watchdog(Masquerading)			|0046b768	|u_svchost.exe_0046b768	unicode u"svchost.exe"
Process Injection for Watchdog(Masquerading)			|0046b780	|u_rmclient.exe_0046b780	unicode u"rmclient.exe"
Process Injection for Watchdog(Masquerading)			|0046b79c	|u_fsutil.exe_0046b79c	unicode u"fsutil.exe"


Local recon (1/3) | b | c 
---|---|--- 
Email, likely data dump						            |0046b7f8	|s_FoxMailRecovery_0046b7f8	ds "FoxMailRecovery"
Email								                    |0046c17c	|s_/emailAddress=_0046c17c	ds "/emailAddress="


 Shlwapi.dll likely used to query, set and delete keys in registry | b | c 
---|---|--- 
DLL								                        |0046b858	|s_Shlwapi.dll_0046b858	ds "Shlwapi.dll"



 Local recon (2/3) | b | c 
---|---|--- 
txt (likely where gathered system info is stored)		|0046b9d0	|u_\sysinfo.txt_0046b9d0	unicode u"\\sysinfo.txt"
diag								                    |0046ba00	|u_dxdiag_0046ba00	unicode u"dxdiag"
GetCursorInfo							                |0046ba80	|s_GetCursorInfo_0046ba80	ds "GetCursorInfo"



 Seems to be used to play a alert sound on host, reason unknown | b | c 
---|---|--- 
alarm.wav							                    |0046bb70	|s_alarm.wav_0046bb70	ds "alarm.wav"



 Local recon (3/3) | b | c 
---|---|--- 
Checks installed programs via Uninstall		            |0046bd30	|s_Software\Microsoft\Windows\Curre_0046bd30	ds "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"



 Might be used to access data in a online picture to be loaded into for example memory | b | c 
---|---|--- 
image2stream		|0046f5c0	|ds "GdipLoadImageFromStream"
image2stream		|0046f5da	|ds "GdipSaveImageToStream"
DLL			        |0046f674	|ds "gdiplus.dll"
wininet.dll		    |0046f6ce	|ds "WININET.dll"


<br>
<br>

# DEPLOYMENT OF EXTRA TOOLS AS BACKUP IF I MISSED SOMETHING IMPORTANT




### 9. CAPA for extra checks

#### FINDINGS SUMMARY: 
- Encryption: AES, XOR, RC4 KSA & PRGA, OpenSSL ECDSA, HMAC, SHA256.  
- Generates random numbers via WinAPI CryptGenRandom @ 0x432962  
- Also the malware has the ability to create suspended processes & Process Hollowing.  

#### HOW:
- capa.exe -vv malwarename.exe

#### PROOF:

>Create process suspended  
namespace:  host-interaction/process/create  
author:     william.ballenthin@mandiant.com  
scope:      basic block  
mbc:        Process::Create Process::Create Suspended Process [C0017.003]  
<br>
basic block @ 0x417344 in function 0x417245    
number: 0x4 = CREATE_SUSPENDED @ 0x417362   
or:  
api: CreateProcess @ 0x41736C	  

		
--------------------------------------------------

>Use process replacement  
namespace:   host-interaction/process/inject  
author:      william.ballenthin@mandiant.com  
scope:       function  
att&ck:      Defense Evasion::Process Injection::Process Hollowing [T1055.012], Defense Evasion::Reflective Code Loading [T1620]  
references:  http://www.autosectools.com/process-hollowing.pdf, https://www.andreafortuna.org/2017/10/09/understanding-process-hollowing/  
<br>
function @ 0x417245  
  and:  
  <br>
    match: create process suspended @ 0x417344  
      and:  
        or:  
          number: 0x4 = CREATE_SUSPENDED @ 0x417362  
        or:  
          api: CreateProcess @ 0x41736C  
          <br> 
    match: write process memory @ 0x417245  
      or:  
        api: WriteProcessMemory @ 0x417558  
        <br>
    match: resume thread @ 0x41757F  
      or:  
        api: ResumeThread @ 0x417582  





# DECRYPTING REMOCOS RAT CONFIG FILE 



### 10. Using Capa findings regarding RC4 - Decrypting config file with CFF Explorer VIII & Cyberchef 

#### FINDINGS SUMMARY: 
- Three domains:  
- License key: 8FBF0123A853BB276AFD9A03F573AE61  
(Previously also observed added to registry:  
Operation: RegSetValue  
Path: HKCU\Software\Rmcghghyrtssxr-7RL1P2\licence  
Result: SUCCESS  
Type: REG_SZ  
Data: 8FBF0123A853BB276AFD9A03F573AE61)  


#### HOW & PROOF:

- Using CFF Explorer  
Loading the malware binary and in the left pane going to Resource Editor, then in the second to left pane clicking RCData and it's subfolder called "SETTINGS" (which contains the config file for the malware, as well as the first byte as RC4 key length and the RC4 key itself.

- Lookin at the Hex shown in CFF Explorer:  
First byte: 66 (is the size of RC4 key)

- Which means RC4 key is the 66 bytes following the first byte above (hex 66):  
>208A19018A5F3F1DA2278174B4326D6052312F542D852956E5989A18EF7F9982CE4AC9DA37E169D8DC48B841069ED5F3244A8473FC0A86543FF271247C8F37ACDC94B9A51D02304199822E167575915D31F3AB902FAB6BC9FB79597B690DA865B801BADA7337

- And the Hex data after the first byte and the RC4 key; is the config file to be decrypted:  
>FB64D359C9476D1EC65250D243F87E5903C1AD604BC396AFC492D927D439691E9782D6C745A6515C56B7F1E888E83C8EE40F0476FCEC458D6D049313448781961FB7EDC5C99D465EF081AF4630C6AC137B551B6A9F05E155C193B4600B747FF6C498C914D35DA1C20CC405416BDD717C8CD6705560DF811D7B4AAF2EAF27FE08C134C46F73C2B611643A095B1EB92A8F2A768EA553AB6863312DED25C574E81858355F1579E59161AB0685C1FACBE775FF0FFE4C891BD973948434EBAB05D504B4DE8A6688EFE5A5E4DD2D4BDACA5DB3C473C529CC9F3F158E460B2BAD2AA2585024EDD062FAF79D6BF470708D92335535A155BFB5C253D3878C9E9D670B5DFC8FF506A8BFAE833309192262C26991078690A9B39555FDAC2DC2DFF339EF4A9AB90D27AAB289B713873F32C10520415D95807FD1FE3435C802EAD0349D5D9AF603C5B27A7B3A95B7C8A5809216E5B432557435E356BA295348CA4E78426C71A1FED2EAFAE281C17080986B0C90468563F48F4B924308AF974D87DA9D6FE3DEA76686BBC5837D065AF69E4E2840E24613F75E9741DCB6D20AB63E96594C2FF32313C8BAB3CB475EC1371889928F03209766D4D03F41CF3EC62FFDF6C72CA5E8011D37FDAA32784D29D1949883C02D46354BA0F9656035186000FA129164E54ED8EA9EF891C3B9C0EDC96C974123DF48EE521824C877E1DC3514C155D5C1CF3FD647EB8C47455DDE993308E98840C0EBAC0C49E7E47ADFC8E4586A070BBBD09127864063EBC8AB9E741F0FFE8FB1C73BCBD995A860AC92DCF70BA8A452B017505EBD59716C44E6B993AFB8D2C333E78E99F6451E321E2F7B48E0777B6447F79A1BD0F6E6847BCB724660D4A7B444284F13FB1D81887939A9DC3ECAE3528BAE758DC4E2749FA7781372965FD1FED86FE9397B88E770857A7FE3E34E43BA2FA2576CCE7AE3EA087D9EFEEEC916080291BDE6E39FDD7DF2B7BC64B661C209D5AD5F2EE374AF691B6C08C2A482D19CBF6F67459FA1E91EC5BE1D81594FE391EB16D7C7F868FA15F946E7A41ABBF4CCA902E84821E5090281504DAF97D370C0613DEE7F200F1340E7A882BB6DB31C39F26224FC88C0E6E8BA0C6CA7349FCA2F4C8B5B89075230B840091B1FF375CB66CC9667AB3BCA74DE4042E28EA7CA8DD3B3CA718BD631688BA2D05C72EDB4D98C0EE5ED6CCB6CEEC739596377DB72F962A664BAE147F803BA7F5EFEAC7749481B30E8837A7F0B2CC4979EB91AF024645A2EEBB5626F204A5E02A27403D09A0BD4DAF9C87875D0A592ABC9B4819DC587910EA0D84A873390B9E048769BFBC47C6EF01F3FE151D14A8CA76F6B191B8B3C72BFC3847B3C9419874C6DD680D0D83618864AAB8A1DDCCF7DFF7B8239B34E2090B077FE83B310349C1DB681959190459E1737B1EFE33F6620F0A8CA667EC6E31DB6F652ADB86623B1A71FE6D64943C447A45AE60D93D65F25DF207EF38DF546AEC53AFEDD53A354B6D1EE120F37D1A647DC16FFCF78701B83B1B7A5FA02843ECED39228173138F9D63EAC2007B3B2113A2DB1C9FBEB30A2FB0260F21E436A45E0798920853C4FC11766DFF8E2899CF92B703CA7C1FDDCF7B6174E7E1E0DE73F26C4FB60121B3382C7121CDDBA09C2A8673871C9ACCE7E672C3BADBE8CCE73D7771C4A5E7F7F6A5222A18B82121000EDCD4905




- Using Cyberchef  
Adding this to Cyberchef RC4 decryptor with key and input as hex format in dropdowns, reveals:  
rem.pushswroller[.]eu:23101  
firewarzone.ydns[.]eu:23101  
sun.drillmmcsnk[.]eu:23101  
remcos.exe  
Rmcghghyrtssxr-7RL1P2  
logs.dat  
Screenshots  
MicRecords  
8FBF0123A853BB276AFD9A03F573AE61  


- Full raw code decrypted but not cleaned below:  
>rem.pushswroller[.]eu:23101:1firewarzone.ydns[.]eu:23101:1sun.drillmmcsnk[.]eu:23101:1||NEW||1|| ||||||1||0|| ||8||r e m c o s . e x e   || || ||0||Rmcghghyrtssxr-7RL1P2||1||8||l o g s . d a t   || || || ||10|| ||  ||5||6||Screenshots|| || || || || || || || || ||5||1||MicRecords|| ||0||0||  || ||||0|| ||1||R e m c o s   ||r e m c o s   || || ||8FBF0123A853BB276AFD9A03F573AE61|| ||0þ0¦ ]({ä´ ©´fª²âæ1ßX0
*†HÎ=0 0"19700101000000Z20901231000000Z0 0Y0 *†HÎ=*†HÎ= B Š¹U5
FºÎÙ¥•µÉ
ÈˆÓyè­’ääÍeTJX‰F„šn¹I>¥?q½žŸª¸[RÛZèÙè‘ƒ`ysv0
*†HÎ=G 0D JW†ùµ’ñÒ@£Ïîçn¡å_L	U×8}ŽO}a1 O}	7”³È²s+v£h‰a—üÏí[ó/DÑ1”Æ||0w GêèaQD¼DÚÅI¢I¥{xiûUëÐ›ÖÐ‰IÀPA)° 
*†HÎ= ¡DB Š¹U5
FºÎÙ¥•µÉ
ÈˆÓyè­’ääÍeTJX‰F„šn¹I>¥?q½žŸª¸[RÛZèÙè‘ƒ`ysv||0‚ 0¦ %ºsùµl€)¡Ò’E§Üï,0
*†HÎ=0 0"19700101000000Z20901231000000Z0 0Y0 *†HÎ=*†HÎ= B Œ‚ª"£'Á<B}
§*
¤ÝFö’mCQ•¹‘iäÑ¸ö€ %’ú´5Y¡Þ`ÏRö$KIãÜ-’É22—%0
*†HÎ=I 0F! Ö|~<‚xc—‘o.ñaK ¼óøòânV¬! ëêð»#%µ‹ˆÊÈñŠUåýµ)ƒ|Â Ì˜¾X|Ã±¥||



- Above can be split in Cyberchef by the repeating characters seen after the most readable parts ("||") as well as removal of NULL & Whitespaces, yielding:  
>rem.pushswroller[.]eu:23101:1firewarzone.ydns[.]eu:23101:1sun.drillmmcsnk[.]eu:23101:1  
NEW  
1  
  
  
1  
0  
8  
remcos.exe  
0  
Rmcghghyrtssxr-7RL1P2  
1  
8  
logs.dat  
10  
5  
6  
Screenshots  
5  
1  
MicRecords  
0  
0  
  
0  
1  
Remcos  
remcos  
8FBF0123A853BB276AFD9A03F573AE61  
0þ0¦ ]({ä´ ©´fª²âæ1ßX0  
*†HÎ=00"19700101000000Z20901231000000Z00Y0 *†HÎ=*†HÎ= BŠ¹U5  
FºÎÙ¥•µÉ  
ÈˆÓyè­’ääÍeTJX‰F„šn¹I>¥?q½žŸª¸[RÛZèÙè‘ƒ`ysv0  
*†HÎ=G0D JW†ùµ’ñÒ@£Ïîçn¡å_L	U×8}ŽO}a1 O}	7”³È²s+v£h‰a—üÏí[ó/DÑ1”Æ   
0w GêèaQD¼DÚÅI¢I¥{xiûUëÐ›ÖÐ‰IÀPA)°   
*†HÎ= ¡DBŠ¹U5  
FºÎÙ¥•µÉ  
ÈˆÓyè­’ääÍeTJX‰F„šn¹I>¥?q½žŸª¸[RÛZèÙè‘ƒ`ysv  
0‚0¦ %ºsùµl€)¡Ò’E§Üï,0  
*†HÎ=00"19700101000000Z20901231000000Z00Y0 *†HÎ=*†HÎ= BŒ‚ª"£'Á<B}  
§*  
¤ÝFö’mCQ•¹‘iäÑ¸ö€ %’ú´5Y¡Þ`ÏRö$KIãÜ-’É22—%0  
*†HÎ=I0F!Ö|~<‚xc—‘o.ñaK ¼óøòânV¬!ëêð»#%µ‹ˆÊÈñŠUåýµ)ƒ|Â Ì˜¾X|Ã±¥  
