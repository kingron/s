#pragma comment(linker, "/subsystem:console /FILEALIGN:0x200 /opt:nowin98 /IGNORE:4078 /MERGE:.rdata=.text /MERGE:.data=.text /section:.text,ERW")  
  
#define _WIN32_WINNT    0x0500  
#include "winsock2i.h"  
#include <winsock2.h>  
#include <stdio.h>  

#include <Iphlpapi.h>  
#pragma comment(lib, "ws2_32.lib")  
#pragma comment(lib, "Iphlpapi.lib")  
  
//#ifndef _WIN32_WINNT // Allow use of features specific to Windows XP or later.   
//#define _WIN32_WINNT 0x0501 // Change this to the appropriate value to target other versions of Windows.  
//#endif   
  
#define bool int
  
#pragma pack(push, 1)//取消内存大小自动对齐  
  
typedef struct _iphdr      
{     
    unsigned char h_lenver; //4位首部长度+4位IP版本号      
    unsigned char tos; //8位服务类型TOS      
    unsigned short total_len; //16位总长度（字节）      
    unsigned short ident; //16位标识      
    unsigned short frag_and_flags; //3位标志位      
    unsigned char ttl; //8位生存时间 TTL      
    unsigned char proto; //8位协议 (TCP, UDP 或其他)      
    unsigned short checksum; //16位IP首部校验和      
    unsigned int sourceIP; //32位源IP地址      
    unsigned int destIP; //32位目的IP地址      
}IP_HEADER;     
  
typedef struct _tcphdr //定义TCP首部      
{     
    USHORT th_sport; //16位源端口      
    USHORT th_dport; //16位目的端口      
    unsigned int th_seq; //32位序列号      
    unsigned int th_ack; //32位确认号      
    unsigned char th_lenres; //4位首部长度/6位保留字      
    unsigned char th_flag; //6位标志位      
    USHORT th_win; //16位窗口大小      
    USHORT th_sum; //16位校验和      
    USHORT th_urp; //16位紧急数据偏移量      
}TCP_HEADER;      
  
struct //定义TCP伪首部      
{     
    unsigned long saddr; //源地址      
    unsigned long daddr; //目的地址      
    char mbz;     
    char ptcl; //协议类型      
    unsigned short tcpl; //TCP长度      
}psd_header;     
  
  
#pragma pack(pop)  
  
  
CRITICAL_SECTION    _cs;  
  
BOOL    _isLog = FALSE;  
BOOL    _isBanner = FALSE;  
BOOL    _isRangeScan;  
BOOL    _isSinglePort;  
BOOL    _isBreak;  
BOOL    _isMultiplePort;  
  
DWORD   _startIp;  
DWORD   _endIp;  
DWORD   _portToScan;  
DWORD   _portScanSingle;  
DWORD   dword_407090;  
DWORD   _portsTotal;  
DWORD   _threadsUsed;  
DWORD   _totalPortsOpen;  
DWORD   _ipScanned;  
DWORD   _tcpTimeout = 3;  
  
u_long  _bindIpAddr;  
SOCKET  _s; // idb  
LPCSTR  _logFile = "Result.txt"; // idb  
char    _httpRequest[] = "HEAD / HTTP/1.0\r\n\r\n";  
void *  _portsArray;  
  
LONG    _maxThreads;  
HANDLE  _semaphore;  
BOOL    _isHttp = FALSE;  
  
int getrandom(int begin, int end)  
{  
    LARGE_INTEGER tick;   
    QueryPerformanceCounter(&tick);  
    return (begin + tick.LowPart % (end - begin + 1));  
}  
  
  
int help(char * app)  
{  
    printf("Usage:   %s TCP/SYN StartIP [EndIP] Ports [Threads] [/T(N)] [/(H)Banner] [/Save]\n", app);  
    printf("Example: %s TCP 12.12.12.12 12.12.12.254 80 512\n", app);  
    printf("Example: %s TCP 12.12.12.12/24 80 512\n", app);  
    printf("Example: %s TCP 12.12.12.12/24 80 512 /T8 /Save\n", app);  
    printf("Example: %s TCP 12.12.12.12 12.12.12.254 80 512 /HBanner\n", app);  
    printf("Example: %s TCP 12.12.12.12 12.12.12.254 21 512 /Banner\n", app);  
  
    printf("Example: %s TCP 12.12.12.12 1-65535 512\n", app);  
    printf("Example: %s TCP 12.12.12.12 12.12.12.254 21,3389,5631 512\n", app);  
    printf("Example: %s TCP 12.12.12.12 21,3389,5631 512\n", app);  
    printf("Example: %s SYN 12.12.12.12 12.12.12.254 80\n", app);  
    printf("Example: %s SYN 12.12.12.12 1-65535\n", app);  
    printf("Example: %s SYN 12.12.12.12 12.12.12.254 21,80,3389\n", app);  
    return printf("Example: %s SYN 12.12.12.12 21,80,3389\n", app);  
}  
  
BOOL WINAPI ConsoleCtrlHandler(  
  DWORD dwCtrlType   //  control signal type  
  )  
{  
    switch (dwCtrlType)   
    {   
        /* Handle the CTRL-C signal. */  
    case CTRL_C_EVENT:   
    case CTRL_CLOSE_EVENT:   
    case CTRL_BREAK_EVENT:    
    case CTRL_LOGOFF_EVENT:   
    case CTRL_SHUTDOWN_EVENT:  
        printf("CTRL+C Is Pressed                          \n");  
        _isBreak = 1;  
        return TRUE;          
    default:   
        return FALSE;  
    }  
}  
  
bool isWin2K()  
{  
    bool result; // eax@8  
    struct _OSVERSIONINFOA VersionInformation; // [sp+0h] [bp-94h]@2  
      
    VersionInformation.dwOSVersionInfoSize = 148;  
    if ( GetVersionExA(&VersionInformation) )  
    {  
        result = VersionInformation.dwPlatformId == 2 && VersionInformation.dwMajorVersion == 5;  
    }  
    else  
    {  
        result = 0;  
    }  
    return result;  
}  
  
//----- (00403704) --------------------------------------------------------  
bool initWinsock()  
{  
    WSADATA wsaData;  
    return (WSAStartup(0x202u, &wsaData) == 0);  
}  
  
//----- (004040C0) --------------------------------------------------------  
BOOL __cdecl logWriteBuffer(LPCSTR lpFileName, char *lpBuffer)  
{  
    BOOL result; // eax@4  
    HANDLE v4; // eax@3  
    DWORD v5; // eax@5  
    DWORD NumberOfBytesWritten; // [sp+0h] [bp-Ch]@2  
    HANDLE hObject; // [sp+8h] [bp-4h]@3  
    BOOL v8; // [sp+4h] [bp-8h]@5  
  
    hObject = 0;  
    v4 = CreateFileA(lpFileName, 0xC0000000u, 2u, 0, 4u, 0x80u, 0);  
    hObject = v4;  
    if ( v4 == (HANDLE)-1 )  
    {  
        result = 0;  
    }  
    else  
    {  
        SetFilePointer(hObject, 0, 0, 2u);  
        v5 = lstrlen(lpBuffer);  
        v8 = WriteFile(hObject, lpBuffer, v5, &NumberOfBytesWritten, 0);  
        CloseHandle(hObject);  
        result = v8;  
    }  
    return result;  
}  
  
  
//----- (00404147) --------------------------------------------------------  
BOOL __cdecl logWriteTime(LPCSTR lpFileName)  
{  
    DWORD Buffer[64]; // [sp+0h] [bp-110h]@2  
    struct _SYSTEMTIME SystemTime; // [sp+100h] [bp-10h]@3  
      
    GetLocalTime(&SystemTime);  
    wsprintf(  
        (char *)Buffer,  
        "Performing Time: %d/%d/%d %d:%d:%d --> ",  
        SystemTime.wMonth,  
        SystemTime.wDay,  
        SystemTime.wYear,  
        SystemTime.wHour,  
        SystemTime.wMinute,  
        SystemTime.wSecond);  
    return logWriteBuffer(lpFileName, (char *)Buffer);  
}  
  
  
//----- (004041D8) --------------------------------------------------------  
BOOL myRecv(SOCKET s, char *buf, int len)  
{  
    int ret; // eax@10  
    BOOL result; // eax@12  
    struct timeval timeout; // [sp+4h] [bp-110h]@3  
    fd_set readfds; // [sp+10h] [bp-104h]@3  
  
    result = FALSE;  
    timeout.tv_sec = 3;  
    timeout.tv_usec = 0;  
  
    if (_isHttp)  
    {  
        ret = send(s, _httpRequest, sizeof(_httpRequest), 0);  
    }  
      
    FD_ZERO(&readfds);  
    FD_SET(s, &readfds);  
    ret = select(0, &readfds, 0, 0, &timeout);  
    if ( ret && ret != -1 )  
    {  
        if ( FD_ISSET(s, &readfds) )  
        {  
            result = recv(s, buf, len, 0) > 0;  
        }  
    }  
  
    return result;  
}  
  
const char * getBanner(char *response)  
{  
    signed int result; // eax@4  
    signed int v4; // edi@6  
    signed int v5; // edi@9  
    size_t v7; // [sp+0h] [bp-4h]@1  
  
    if ( response )  
    {  
        int len = 0;  
        if (_isHttp)  
        {  
            const char * tag = "Server: ";  
            char * serverBanner = strstr(response, tag);  
            if (!serverBanner)  
            {  
                serverBanner = response;  
            }  
            else  
            {  
                serverBanner += lstrlen(tag);  
            }             
            len = lstrlen(serverBanner);  
            for (int i = 0; i < len; i++)  
            {  
                if (serverBanner[i] == '\r' || serverBanner[i] == '\n')  
                {  
                    serverBanner[i] = '\0';  
                    break;  
                }  
            }  
            return serverBanner;  
        }  
        else  
        {  
            len = lstrlen(response);  
            for (int i = 0; i < lstrlen(response); i++)  
            {  
                if (response[i] == '\r' || response[i] == '\n')  
                {  
                    response[i] = '\0';  
                    break;  
                }  
            }  
        }  
  
        result = 1;  
    }  
    else  
    {  
        result = 0;  
    }  
  return response;  
}  
//----- (004037A8) --------------------------------------------------------  
DWORD WINAPI tcpScanThread(LPVOID lparam)  
{  
  int ret; // eax@5  
  char banner[0x400]; // [sp+0h] [bp-330h]@2  
  u_long hostlong; // [sp+208h] [bp-128h]@3  
  int v9; // [sp+200h] [bp-130h]@3  
  char response[200]; // [sp+114h] [bp-21Ch]@3  
  SOCKET s; // [sp+228h] [bp-108h]@3  
  struct timeval timeout; // [sp+20Ch] [bp-124h]@3  
  u_long argp; // [sp+204h] [bp-12Ch]@3  
  char targetHost[0x200]; // [sp+1E0h] [bp-150h]@3  
  struct sockaddr_in sa; // [sp+214h] [bp-11Ch]@4  
  fd_set writefds; // [sp+22Ch] [bp-104h]@8  
  int recvLen = 0;  
  hostlong = *(DWORD *)lparam;  
  v9 = *((DWORD *)lparam + 1);  
  free(lparam);  
  
  memset(response, 0, sizeof(response));  
  s = -1;  
  timeout.tv_sec = _tcpTimeout;  
  timeout.tv_usec = 0;  
  argp = 1;  
  memset(targetHost, 0, sizeof(targetHost));  
  s = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);  
  if ( s != -1 )  
  {  
    memset(&sa, 0, sizeof(sa));   
    sa.sin_family = AF_INET;   
    sa.sin_addr.s_addr = htonl(hostlong);   
    sa.sin_port = htons(v9);   
    argp = 1;  
    if ( ioctlsocket(s, FIONBIO, &argp) != -1 )  
    {  
      ret = connect(s, (const struct sockaddr *)&sa, sizeof(sa));  
      if ( ret != -1 )  
      {  
        goto __recv;  
      }  
      if ( WSAGetLastError() == WSAEWOULDBLOCK)  
      {  
        FD_ZERO(&writefds);  
        FD_SET(s, &writefds);  
        ret = select(0, 0, &writefds, 0, &timeout);  
  
        if ( FD_ISSET(s, &writefds) )  
        {  
__recv:  
          wsprintf(  
            targetHost,  
            "%d.%d.%d.%d",  
            hostlong >> 24,  
            (hostlong >> 16) & 0xFF,  
            (unsigned __int16)((WORD)hostlong >> 8),  
            (unsigned __int8)hostlong);  
          EnterCriticalSection(&_cs);  
          ++_totalPortsOpen;  
          LeaveCriticalSection(&_cs);  
          const char *  responseBanner = NULL;  
          if ( _isBanner )  
          {  
                  // 切回同步模式  
                argp = 0;  
                ioctlsocket(s, FIONBIO, &argp);  
                recvLen = myRecv(s, response, sizeof(response));  
                EnterCriticalSection(&_cs);  
                if ( recvLen )  
                {  
                  responseBanner = getBanner(response);  
                  if ( lstrlen(responseBanner) <= 6 )  
                    printf("%-16s %-5d -> \"%s\"           \n", targetHost, v9, responseBanner);  
                  else  
                    printf("%-16s %-5d -> \"%s\"\n", targetHost, v9, responseBanner);  
                }  
                else  
                {  
                  printf("%-16s %-5d -> NULL             \n", targetHost, v9);  
                }  
                LeaveCriticalSection(&_cs);  
          }  
          else  
          {  
            EnterCriticalSection(&_cs);  
            printf("%-16s %-5d Open             \n", targetHost, v9);  
            LeaveCriticalSection(&_cs);  
          }  
          if ( _isLog )  
          {  
            memset(banner, 0, sizeof(banner));  
            if ( _isBanner )  
            {  
              if ( recvLen )  
                wsprintf(banner, "%-16s %-5d -> \"%s\"\r\n", targetHost, v9, responseBanner);  
              else  
                wsprintf(banner, "%-16s %-5d -> NULL\r\n", targetHost, v9);  
            }  
            else  
            {  
              wsprintf(banner, "%-16s %-5d Open             \r\n", targetHost, v9);  
            }  
            EnterCriticalSection(&_cs);  
            logWriteBuffer(_logFile, banner);  
            LeaveCriticalSection(&_cs);  
          }  
        }  
      }  
    }  
  }  
  EnterCriticalSection(&_cs);  
  ++_ipScanned;  
  if ( _threadsUsed )  
    --_threadsUsed;  
  ReleaseSemaphore(_semaphore, 1, 0);  
  LeaveCriticalSection(&_cs);  
  closesocket(s);  
  return 0;  
}  
  
USHORT checkSum(void * buffer, int size)   
{   
       unsigned long cksum=0;  
       while (size >1) {  
              cksum += *(USHORT *)buffer;  
              size -= sizeof(USHORT);  
              buffer = (char *)buffer + sizeof(USHORT);  
       }  
       if (size) cksum += *(UCHAR*) buffer;  
       cksum = (cksum >> 16) + (cksum&0xffff);  
       cksum += (cksum >> 16);  
       return (USHORT) (~cksum);   
}   
  
  
int buildSynPacket(char * buf, u_long saddr, u_long sport, u_long daddr, u_long dport)  
{  
    int len = 0;  
    IP_HEADER ip_header;     
    TCP_HEADER tcp_header;  
    //填充IP首部      
    ip_header.h_lenver=(4<<4 | sizeof(ip_header)/sizeof(unsigned long));     
    //高四位IP版本号，低四位首部长度      
    ip_header.total_len=htons(sizeof(IP_HEADER)+sizeof(TCP_HEADER)); //16位总长度（字节）      
    ip_header.ident=1; //16位标识      
    ip_header.frag_and_flags = 0; //3位标志位      
    ip_header.ttl = 128; //8位生存时间TTL      
    ip_header.proto = IPPROTO_TCP; //8位协议(TCP,UDP…)      
    ip_header.checksum = 0; //16位IP首部校验和      
    ip_header.sourceIP = saddr; //32位源IP地址      
    ip_header.destIP = daddr; //32位目的IP地址      
      
      
    //填充TCP首部      
    tcp_header.th_sport = sport; //源端口号      
    tcp_header.th_lenres=(sizeof(TCP_HEADER)/4<<4|0); //TCP长度和保留位      
    tcp_header.th_win = htons(0x4000);      
      
    //填充TCP伪首部（用于计算校验和，并不真正发送）      
    psd_header.saddr=ip_header.sourceIP;     
    psd_header.daddr=ip_header.destIP;     
    psd_header.mbz=0;     
    psd_header.ptcl=IPPROTO_TCP;     
    psd_header.tcpl=htons(sizeof(tcp_header));   
      
      
    tcp_header.th_dport = dport; //目的端口号  
    tcp_header.th_ack=0; //ACK序列号置为0  
    tcp_header.th_flag=2; //SYN 标志  
    tcp_header.th_seq = sport -1; //SYN序列号随机  
    tcp_header.th_urp=0; //偏移  
    tcp_header.th_sum=0; //校验和  
    //计算TCP校验和，计算校验和时需要包括TCP pseudo header   
    memcpy(buf,&psd_header,sizeof(psd_header));   
    memcpy(buf+sizeof(psd_header),&tcp_header,sizeof(tcp_header));  
    tcp_header.th_sum=checkSum(buf,sizeof(psd_header)+sizeof(tcp_header));  
      
    //计算IP校验和  
    memcpy(buf,&ip_header,sizeof(ip_header));  
    memcpy(buf+sizeof(ip_header),&tcp_header,sizeof(tcp_header));  
    memset(buf+sizeof(ip_header)+sizeof(tcp_header),0,4);  
    len=sizeof(ip_header)+sizeof(tcp_header);  
    ip_header.checksum=checkSum(buf,len);  
      
    //填充发送缓冲区  
    memcpy(buf,&ip_header,sizeof(ip_header));  
  
    return len;  
}  
  
// 有点问题，发出去的数据包不对  
signed int synScan()  
{  
  char Buffer[0x190]; // [sp+0h] [bp-2C0h]@2  
  int v8; // [sp+140h] [bp-180h]@3  
  int v9; // [sp+150h] [bp-170h]@3  
  SOCKET s; // [sp+154h] [bp-16Ch]@3  
  char buf[0x100]; // [sp+198h] [bp-128h]@3  
  signed int optval; // [sp+13Ch] [bp-184h]@3  
  signed int sendTimeout; // [sp+138h] [bp-188h]@3  
  unsigned int portsScanned; // [sp+170h] [bp-150h]@3  
  unsigned int v15; // [sp+14Ch] [bp-174h]@3  
  unsigned int v16; // [sp+148h] [bp-178h]@3  
  unsigned int dport; // [sp+178h] [bp-148h]@6  
  unsigned int counter; // [sp+174h] [bp-14Ch]@6  
  u_long hostlong; // [sp+158h] [bp-168h]@6  
  struct sockaddr_in dst; // [sp+17Ch] [bp-144h]@9  
  int len; // [sp+16Ch] [bp-154h]@9  
  unsigned int v49; // [sp+12Ch] [bp-194h]@11  
  char Dest[0x20]; // [sp+110h] [bp-1B0h]@37  
  
  
  
  v8 = _portScanSingle;  
  v9 = dword_407090;  
  s = -1;  
  
  
  memset(buf, 0, sizeof(buf));  
  optval = 1;  
  sendTimeout = 1500;  
  portsScanned = 0;  
  v15 = 0;  
  v16 = 0;  
  s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);  
  if ( s != -1 )  
  {  
    optval = 1;  
    if ( setsockopt(s, IPPROTO_IP, 2/*IP_HDRINCL*/, (const char *)&optval, sizeof(optval)) != -1 )  
    {  
      if ( setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&sendTimeout, sizeof(sendTimeout)) != -1 )  
      {  
        dport = 0;  
        counter = 0;  
        hostlong = _startIp;  
        while ( hostlong <= _endIp )  
        {  
          if ( _isMultiplePort )  
          {  
            counter = 0;  
            while ( counter < _portsTotal )  
            {  
              dport = *((DWORD *)_portsArray + counter);  
  
              memset(&dst, 0, sizeof(dst));  
  
              dst.sin_family = AF_INET;  
              dst.sin_port = htons(dport);  
              dst.sin_addr.s_addr = htonl(hostlong);   
  
              len = buildSynPacket(buf, _bindIpAddr, htons(getrandom(1, 65535)), dst.sin_addr.s_addr, dst.sin_port);  
  
              ++_ipScanned;  
  
              if ( sendto(s, buf, len, 0, (struct sockaddr *)&dst, sizeof(dst)) != -1 )  
              {  
                ++portsScanned;  
                EnterCriticalSection(&_cs);  
                if ( _isRangeScan )  
                {  
                  printf("%u Ports Scanned.              \r", portsScanned);  
                }  
                else  
                {  
                  v49 = portsScanned / _portsTotal;  
                  printf("%u IP Scanned.              \r", portsScanned / _portsTotal);  
                }  
                LeaveCriticalSection(&_cs);  
                if ( _isBreak )  
                {  
                  v15 = hostlong + 1;  
                  v16 = dport;  
                  goto __break;  
                }  
                if ( !(portsScanned % 1000) )  
                  Sleep(0xAu);  
              }  
              ++counter;  
            }  
          }  
          else // !_isMultiplePort  
          {  
            v49 = v9 - v8 + 1;  
            counter = v8;  
            while ( counter <= v9 )  
            {  
              dport = counter;  
  
              memset(&dst, 0, sizeof(dst));  
              dst.sin_family = AF_INET;  
              dst.sin_port = htons(dport);  
              dst.sin_addr.s_addr = htonl(hostlong);   
                
              len = buildSynPacket(buf, _bindIpAddr, htons(getrandom(1, 65535)), dst.sin_addr.s_addr, dst.sin_port);  
  
              ++_ipScanned;  
              if ( sendto(s, buf, len, 0, (struct sockaddr *)&dst, sizeof(dst)) != -1 )  
              {  
                ++portsScanned;  
                EnterCriticalSection(&_cs);  
                if ( _isRangeScan )  
                {  
                  printf("%u Ports Scanned.              \r", portsScanned);  
                }  
                else  
                {  
                  printf("%u IP Scanned.              \r", portsScanned / v49);  
                }  
                LeaveCriticalSection(&_cs);  
                if ( _isBreak )  
                {  
                  if ( _isRangeScan )  
                    v15 = hostlong;  
                  else  
                    v15 = hostlong + 1;  
                  v16 = dport;  
                  goto __break;  
                }  
                if ( !(portsScanned % 1000) )  
                  Sleep(10);  
              }  
              ++counter;  
            }  
          }  
          ++hostlong;  
        }  
      }  
    }  
  }  
  
__break:  
  if ( _isBreak )  
  {  
    memset(Dest, 0, sizeof(Dest));  
    wsprintf(Dest, "%d.%d.%d.%d", v15 >> 24, (v15 >> 16) & 0xFF, (unsigned __int16)((WORD)v15 >> 8), (unsigned __int8)v15);  
    printf("Last Scan: %s:%d                \n", Dest, v16);  
    if ( _isLog )  
    {  
      wsprintf(Buffer, "LastIP Scanned: %s:%d\r\n", &Dest, v16);  
      logWriteBuffer(_logFile, (char *)Buffer);  
    }  
  }  
  if ( s != -1 )  
    closesocket(s);  
  
  EnterCriticalSection(&_cs);  
  if ( _threadsUsed )  
    --_threadsUsed;  
  LeaveCriticalSection(&_cs);  
  return 1;  
}  
  
//----- (00403FD9) --------------------------------------------------------  
BOOL buildPortsList(char * portsList, int portsCount)  
{  
    BOOL    result; // eax@4  
    int     port; // eax@8  
    char *  nextToken; // eax@5  
    char *  portString; // [sp+4h] [bp-8h]@5  
  
    _portsArray = malloc(sizeof(int) * portsCount);  
  
    result = FALSE;  
  
    if ( _portsArray )  
    {  
        nextToken = strtok(portsList, ",");  
        portString = nextToken;  
        if ( nextToken )  
        {  
            while ( portString )  
            {  
                port = atoi(portString);  
                if ( port > 0 )  
                {  
                    if ( port <= 65535 )  
                    {  
                        *((DWORD *)_portsArray + _portsTotal++) = port;  
                    }  
                }  
                portString = strtok(0, ",");  
            }  
  
            result = (_portsTotal > 0);  
        }  
    }  
  
    return result;  
}  
  
//----- (00403F08) --------------------------------------------------------  
int getPortsCount(char * portList)  
{  
    int     result; // eax@4  
    char *  nextToken; // eax@7  
    char *  buf; // [sp+4h] [bp-Ch]@5  
    char *  p; // [sp+Ch] [bp-4h]@7  
    int     count; // [sp+8h] [bp-8h]@9  
      
    if ( portList )  
    {  
        buf = (char *)malloc(lstrlen(portList) + 16);  
        if (buf)  
        {  
            strcpy(buf, portList);  
            nextToken = strtok(buf, ",");  
            p = nextToken;  
            if (nextToken)  
            {  
                count = 0;  
                while ( p )  
                {  
                    p = strtok(0, ",");  
                    count++;  
                }  
                result = count;  
            }  
            else  
            {  
                result = 0;  
            }  
            free(buf);  
        }  
        else  
        {  
            result = 0;  
        }  
    }  
    else  
    {  
        result = 0;  
    }  
    return result;  
}  
//----- (00402A70) --------------------------------------------------------  
signed int __cdecl filterPacket(char * a1)  
{  
  signed int result; // eax@4  
  u_long v3; // eax@5  
  unsigned int v4; // eax@20  
  u_short v5; // ax@20  
  char * v8; // [sp+144h] [bp-8h]@3  
  unsigned __int16 v9; // [sp+13Eh] [bp-Eh]@3  
  char * v10; // [sp+148h] [bp-4h]@3  
  u_long v11; // [sp+140h] [bp-Ch]@5  
  signed int v12; // [sp+134h] [bp-18h]@9  
  unsigned int v13; // [sp+138h] [bp-14h]@9  
  unsigned int v14; // [sp+130h] [bp-1Ch]@10  
  char  buf[0x20]; // [sp+110h] [bp-3Ch]@20  
  char  logBuffer[0x100];  
  unsigned int v16; // [sp+10Ch] [bp-40h]@20  
  int v17; // [sp+108h] [bp-44h]@20  
  int v18; // [sp+104h] [bp-48h]@20  
  int v19; // [sp+100h] [bp-4Ch]@20  
  
  v8 = a1;  
  v9 = 4 * (*(BYTE *)a1 & 0xF);  
  v10 = a1 + v9;  
  if ( *(BYTE *)(a1 + v9 + 13) == 20 )  
  {  
    result = 0;  
  }  
  else  
  {  
    v3 = ntohl(*(DWORD *)(v8 + 12));  
    v11 = v3;  
    if ( v3 >= _startIp && v3 <= _endIp )  
    {  
      if ( *(BYTE *)(v10 + 13) != 18 )  
        goto LABEL_26;  
      v12 = 0;  
      v13 = ntohs(*(WORD *)v10);  
      if ( !_isMultiplePort )  
      {  
        if ( v13 >= _portScanSingle )  
        {  
          if ( v13 <= dword_407090 )  
            v12 = 1;  
        }  
      }  
      else  
      {  
        v14 = 0;  
        while ( v14 < _portsTotal )  
        {  
          if ( v13 == *((DWORD *)_portsArray + v14) )  
            v12 = 1;  
          ++v14;  
        }  
      }  
      if ( v12 )  
      {  
        memset(buf, 0, sizeof(buf));  
        v4 = ntohl(*(DWORD *)(v8 + 12));  
        v14 = v4;  
        v16 = v4 >> 24;  
        v17 = (v4 >> 16) & 0xFF;  
        v18 = (unsigned __int16)((WORD)v4 >> 8);  
        v19 = (unsigned __int8)v4;  
        wsprintf(  
          buf,  
          "%d.%d.%d.%d",  
          v4 >> 24,  
          (v4 >> 16) & 0xFF,  
          (unsigned __int16)((WORD)v4 >> 8),  
          (unsigned __int8)v4);  
        EnterCriticalSection(&_cs);  
        ++_totalPortsOpen;  
        v5 = ntohs(*(WORD *)v10);  
        printf("%-16s %-5d Open             \n", buf, v5);  
        if ( _isLog )  
        {  
          wsprintf(logBuffer, "%-16s %-5d Open             \r\n", buf, v5);  
          logWriteBuffer(_logFile, logBuffer);  
        }  
        LeaveCriticalSection(&_cs);  
        result = 1;  
      }  
      else  
      {  
LABEL_26:  
        result = 0;  
      }  
    }  
    else  
    {  
      result = -1;  
    }  
  }  
  return result;  
}  
#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)   
  
DWORD WINAPI snifferThread(LPVOID)  
{  
    int ret;  
  
    //设置SOCK_RAW为SIO_RCVALL，以便接收所有的IP包      
    int optval = 1;  
    int bytesRet;    
      
    SOCKADDR_IN sa;   
    _s = socket(AF_INET, SOCK_RAW, IPPROTO_IP);  
    if (INVALID_SOCKET == _s)  
    {  
        printf("Fail To Create Socket\n");  
        return 0;  
    }  
    sa.sin_family = AF_INET;  
    sa.sin_port = htons(0);  
    sa.sin_addr.S_un.S_addr = _bindIpAddr;  
      
    ret = bind(_s, (struct sockaddr *)&sa, sizeof(sa));     
    if (INVALID_SOCKET == ret)  
    {  
        printf("Fail To Bind Socket\n");  
        closesocket(_s);  
        goto __faild;  
    }  
  
    ret = WSAIoctl(_s, SIO_RCVALL, (LPVOID)&optval, sizeof(optval), NULL, 0, (LPDWORD)&bytesRet, NULL, NULL);  
  
    char    buff[0xFFFF];  
      
    do  
    {  
        memset(buff, 0, sizeof(buff));  
        ret = recv(_s, buff, sizeof(buff), 0);  
        if (ret)  
        {  
            filterPacket(buff);  
        }  
    } while (ret > 0);  
  
      
__faild:      
    return 0;  
}  
  
u_long getBindIpAddress(char * dstIpAddr)  
{  
    u_long  bindAddr = INADDR_NONE;  
    DWORD   nInterfaceIndex = 0;  
    DWORD   index = 0;  
    PMIB_IPADDRTABLE    ipTable = NULL;  
    ULONG   allocSize = 0;  
    HRESULT ret;  
      
    ret = GetBestInterface( inet_addr(dstIpAddr), &nInterfaceIndex );  
      
    if (ret != NO_ERROR)  
    {  
        goto __exit;  
    }  
      
    /* 
    MIB_IFROW ifRow; 
    ifRow.dwIndex = nInterfaceIndex; 
    ret = GetIfEntry( &ifRow ); 
     
      if ( ret != NO_ERROR ) 
      { 
      goto __exit; 
      } 
       
        printf("%s\n", ifRow.bDescr); 
    */  
      
    allocSize = 0;    
      
    do  
    {  
        ret = GetIpAddrTable( ipTable, &allocSize, FALSE );  
        if (ret != NO_ERROR)  
        {  
            if (allocSize)  
            {  
                ipTable = (PMIB_IPADDRTABLE)malloc(allocSize);  
            }  
        }  
    } while (ret != NO_ERROR);  
      
    for (index = 0; index < ipTable->dwNumEntries; index++)  
    {  
        if (ipTable->table[ index ].dwIndex == nInterfaceIndex)  
        {  
            bindAddr = ipTable->table[ index ].dwAddr;  
            break;  
        }  
    }  
      
__exit:  
    if (ipTable)  
    {  
        free(ipTable);  
    }  
    return bindAddr;  
}  
  
void buildIpRange(char * startIpAddr, char * realStartIpAddr, char * realEndIpAddr)  
{  
    char    startIpStr[256];  
    char    endIpStr[256];  
    char *  slash = NULL;  
    int     range = 0;  
    int     submask = 0;  
      
    memset(startIpStr, 0, sizeof(startIpStr));  
    memset(endIpStr, 0, sizeof(endIpStr));  
      
    slash = strchr(startIpAddr, '/');  
    if (slash)  
    {  
        lstrcpyn(startIpStr, startIpAddr, slash - startIpAddr + 1);  
        int bit = atoi(slash+1);  
        range = 0xFFFFFFFF >> bit;  
        submask = 0xFFFFFFFF << (32 - bit);  
    }  
    else  
    {  
        lstrcpy(startIpStr, startIpAddr);  
    }  
      
    // 起始IP参数转化(支持域名)  
    struct hostent * hostInfo = gethostbyname(startIpStr);  
    if (hostInfo)  
    {  
        lstrcpy(startIpStr, inet_ntoa(*(IN_ADDR*)hostInfo->h_addr_list[0]));  
    }  
      
    if (submask)  
    {  
        int start = (inet_addr(startIpStr) & ntohl(submask)) + ntohl(1);  
        int end = (inet_addr(startIpStr) & ntohl(submask)) + ntohl(range-1);  
        lstrcpy(endIpStr, inet_ntoa(*(IN_ADDR*)&end));  
        lstrcpy(startIpStr, inet_ntoa(*(IN_ADDR*)&start));  
    }  
      
    if (realStartIpAddr)  
    {  
        lstrcpy(realStartIpAddr, startIpStr);  
    }  
      
    if (realEndIpAddr)  
    {  
        lstrcpy(realEndIpAddr, endIpStr);  
    }  
}  
  
  
int startScan(char * scanType, char * startIpAddr, char * endIpAddr, char * portList, char *maxThreads)  
{  
    char    buf[0x100];  
    char    lastScan[0x20];  
    signed int v5; // ecx@1  
    unsigned __int32 v8; // eax@19  
    unsigned __int32 v9; // eax@19  
    unsigned __int32 startIp; // eax@23  
    int v11; // eax@26  
    int v12; // eax@27  
    int v13; // eax@35  
    HANDLE threadSniffer; // eax@62  
    HANDLE v17; // eax@120  
    void *param; // eax@129  
    DWORD v20; // eax@149  
    int v21; // eax@160  
    unsigned int v22; // ecx@177  
    unsigned int v23; // [sp+0h] [bp-27Ch]@2  
    signed int isSynScan; // [sp+260h] [bp-1Ch]@3  
    int v25; // [sp+28h] [bp-254h]@3  
    int v26; // [sp+26Ch] [bp-10h]@3  
    unsigned int lastPortScan; // [sp+268h] [bp-14h]@3  
    BOOL v29; // [sp+264h] [bp-18h]@3  
    int count; // [sp+270h] [bp-Ch]@3  
    int currentIp; // [sp+14h] [bp-268h]@26  
    DWORD timeStart; // [sp+4Ch] [bp-230h]@60  
    DWORD ThreadId; // [sp+274h] [bp-8h]@62  
    HANDLE hObject; // [sp+278h] [bp-4h]@62  
    unsigned int v37; // [sp+10h] [bp-26Ch]@116  
    unsigned int portIndex; // [sp+Ch] [bp-270h]@118  
    LPVOID lpParameter; // [sp+8h] [bp-274h]@119  
    unsigned int v45; // [sp+25Ch] [bp-20h]@160  
    unsigned int hoursElapsed; // [sp+58h] [bp-224h]@162  
    unsigned int minutesElapsed; // [sp+54h] [bp-228h]@162  
  unsigned int secondsElapsed; // [sp+50h] [bp-22Ch]@162  
  
  LONG previousCount;  
  char  realStartIpAddr[200];  
  char  realEndIpAddr[200];  
  
    isSynScan = 0;  
    v5 = 159;  
    v25 = 0;  
    v26 = 0;  
    lastPortScan = 0;  
    v29 = 0;  
    count = 0;  
    _portsTotal = 0;  
  
    if ( !initWinsock() )  
    {  
        printf("Fail To Init Socket\n");  
        return 0;  
    }  
          
    // www.shangdu.com/24 1.1.1.1/16  
    //////////////////////////////////////////////////////////////////////////  
    memset(realStartIpAddr, 0, sizeof(realStartIpAddr));  
    memset(realEndIpAddr, 0, sizeof(realEndIpAddr));  
    if (endIpAddr)  
    {  
        lstrcpy(realEndIpAddr, endIpAddr);  
    }  
    buildIpRange(startIpAddr, realStartIpAddr, realEndIpAddr);  
    startIpAddr = realStartIpAddr;  
  
    if (lstrlen(realEndIpAddr) > 0)  
    {  
        endIpAddr = realEndIpAddr;  
    }  
  
    //////////////////////////////////////////////////////////////////////////  
  
    memset(lastScan, 0, sizeof(lastScan));  
    memset(buf, 0, sizeof(buf));  
  
    if ( lstrcmpi(scanType, "SYN") && lstrcmpi(scanType, "TCP") )  
    {  
        printf("Invalid Scan Type\n");  
        return 0;  
    }  
    if ( lstrcmpi(scanType, "SYN") )  
    {  
        _maxThreads = atoi(maxThreads);  
        if ( !_maxThreads || (unsigned int)_maxThreads > 0x400 )  
        {  
            printf("Max Thread Out Of Bound\n");  
            return 0;  
        }  
    }  
    else  
    {  
        isSynScan = 1;  
        if ( !isWin2K() )  
        {  
            printf("SYN Scan Can Only Perform On WIN 2K Or Above\n");  
            return 0;  
        }  
        _maxThreads = 1;  
    }  
  
    if (!endIpAddr)  
    {  
        _isRangeScan = 1;  
    }  
    if ( !strstr(portList, "-") )  
    {  
        if ( !strstr(portList, ",") )  
            _isSinglePort = 1;  
    }  
    if ( _isRangeScan )  
    {  
        startIp = inet_addr(startIpAddr);  
        _startIp = ntohl(startIp);  
        _endIp = _startIp;  
    }  
    else  
    {  
        v8 = inet_addr(startIpAddr);  
        _startIp = ntohl(v8);  
        v9 = inet_addr(endIpAddr);  
        _endIp = ntohl(v9);  
        if ( _startIp > _endIp )  
        {  
            printf("Invalid Hosts To Scan\n");  
            return 0;  
        }  
        if ( _endIp == _startIp )  
            _isRangeScan = 1;  
    }  
    if (!_isSinglePort)  
    {  
        //////////////////////////////////////////////////////////////////////////  
        if ( strstr(portList, "-") )  
        {  
            v11 = (int)strtok(portList, "-");  
            currentIp = v11;  
            if ( !v11 )  
            {  
                printf("Something Wrong About The Ports\n");  
                return 0;  
            }  
            _portScanSingle = atoi((const char *)currentIp);  
            v12 = (int)strtok(0, "-");  
            currentIp = v12;  
            if ( v12 )  
                dword_407090 = atoi((const char *)currentIp);  
            if ( !_portScanSingle || (unsigned int)dword_407090 > 0xFFFF || _portScanSingle > (unsigned int)dword_407090 )  
            {  
                printf("Invalid Port To Scan\n");  
                return 0;  
            }  
        }  
        else  
        {  
            if ( !strstr(portList, ",") )  
            {  
                printf("Invalid Port List\n");  
                return 0;  
            }  
            v13 = getPortsCount(portList);  
            currentIp = v13;  
            if ( !v13 )  
            {  
                printf("No Port To Scan\n");  
                return 0;  
            }  
            _isMultiplePort = buildPortsList(portList, currentIp);  
            if ( _isMultiplePort )  
            {  
                _isSinglePort = (unsigned int)_portsTotal <= 1;  
            }  
        }  
    }  
  else  
  {  
    _portToScan = atoi(portList);  
    if ( !_portToScan || _portToScan > 0xFFFF )  
    {  
      printf("Invalid Port To Scan\n");  
      return 0;  
    }  
    _portScanSingle = _portToScan;  
    dword_407090 = _portToScan;  
  }  
    if ( !isSynScan )  
    {  
      _semaphore = CreateSemaphoreA(0, _maxThreads, _maxThreads, 0);  
      if ( !_semaphore )  
      {  
        printf("Fail To Create Semaphore\n");  
        if ( _portsArray )  
          free(_portsArray);  
        return 0;  
      }  
    }  
   
    _bindIpAddr = getBindIpAddress(startIpAddr);  
  
    if (INADDR_NONE == _bindIpAddr)  
    {  
        goto __faild;  
    }  
    timeStart = GetTickCount();  
    if ( isSynScan )  
    {  
        printf("Bind On IP: %d.%d.%d.%d\n\n", (_bindIpAddr & 0x0000ff),  
            ((_bindIpAddr & 0x00ff00) >> 8), ((_bindIpAddr & 0xff0000 ) >> 16), (_bindIpAddr >> 24));  
  
        threadSniffer = CreateThread(0, 0, snifferThread, 0, 0, &ThreadId);  
        hObject = threadSniffer;  
        if (NULL == threadSniffer)  
        {  
            goto __faild;  
        }  
      CloseHandle(hObject);  
    }  
    if ( _isLog )  
    {  
      logWriteBuffer(_logFile, "-------------------------------------------------------------------------------\r\n");  
      logWriteTime(_logFile);  
    }  
    if ( _isRangeScan || _isSinglePort )  
    {  
      if ( (!_isRangeScan) & _isSinglePort )  
      {  
        if ( isSynScan )  
        {  
          printf("SYN Scan: About To Scan %u IP Using %d Thread\n", _endIp - _startIp + 1, _maxThreads);  
          if ( _isLog )  
          {  
            wsprintf(  
              buf,  
              "SYN Scan: About To Scan %u IP Using %d Thread\r\n",  
              _endIp - _startIp + 1,  
              _maxThreads);  
            logWriteBuffer(_logFile, buf);  
          }  
        }  
        else  
        {  
          printf("Normal Scan: About To Scan %u IP Using %d Threads\n", _endIp - _startIp + 1, _maxThreads);  
          if ( _isLog )  
          {  
            wsprintf(  
              buf,  
              "Normal Scan: About To Scan %u IP Using %d Threads\r\n",  
              _endIp - _startIp + 1,  
              _maxThreads);  
            logWriteBuffer(_logFile, buf);  
          }  
        }  
      }  
      else  
      {  
        if ( (!_isRangeScan || _isSinglePort) )  
        {  
          if ( _isRangeScan )  
          {  
            if ( _isSinglePort )  
            {  
              if ( isSynScan )  
              {  
                if ( _isMultiplePort )  
                {  
                  printf("SYN Scan: About To Scan %s:%d Using %d Thread\n", startIpAddr, *(DWORD *)_portsArray, _maxThreads);  
                  if ( _isLog )  
                  {  
                    wsprintf(  
                      buf,  
                      "SYN Scan: About To Scan %s:%d Using %d Thread\r\n",  
                      startIpAddr,  
                      *(DWORD *)_portsArray,  
                      _maxThreads);  
                    logWriteBuffer(_logFile, buf);  
                  }  
                }  
                else  
                {  
                  printf("SYN Scan: About To Scan %s:%d Using %d Thread\n", startIpAddr, _portScanSingle, _maxThreads);  
                  if ( _isLog )  
                  {  
                    wsprintf(  
                      buf,  
                      "SYN Scan: About To Scan %s:%d Using %d Thread\r\n",  
                      startIpAddr,  
                      _portScanSingle,  
                      _maxThreads);  
                    logWriteBuffer(_logFile, buf);  
                  }  
                }  
              }  
              else  
              {  
                if ( _isMultiplePort )  
                {  
                  printf("Normal Scan: About To Scan %s:%d Using %d Thread\n", startIpAddr, *(DWORD *)_portsArray, _maxThreads);  
                  if ( _isLog )  
                  {  
                    wsprintf(  
                      buf,  
                      "Normal Scan: About To Scan %s:%d Using %d Thread\r\n",  
                      startIpAddr,  
                      *(DWORD *)_portsArray,  
                      _maxThreads);  
                    logWriteBuffer(_logFile, buf);  
                  }  
                }  
                else  
                {  
                  printf("Normal Scan: About To Scan %s:%d Using %d Thread\n", startIpAddr, _portScanSingle, _maxThreads);  
                  if ( _isLog )  
                  {  
                    wsprintf(  
                      buf,  
                      "Normal Scan: About To Scan %s:%d Using %d Thread\r\n",  
                      startIpAddr,  
                      _portScanSingle,  
                      _maxThreads);  
                    logWriteBuffer(_logFile, buf);  
                  }  
                }  
              }  
            }  
          }  
        }  
        else  
        {  
          if ( isSynScan )  
          {  
            if ( _isMultiplePort )  
            {  
              printf("SYN Scan: About To Scan %u Ports Using %d Thread\n", _portsTotal, _maxThreads);  
              if ( _isLog )  
              {  
                wsprintf(buf, "SYN Scan: About To Scan %u Ports Using %d Thread\r\n", _portsTotal, _maxThreads);  
                logWriteBuffer(_logFile, buf);  
              }  
            }  
            else  
            {  
              printf(  
                "SYN Scan: About To Scan %u Ports Using %d Thread\n",  
                dword_407090 - _portScanSingle + 1,  
                _maxThreads);  
              if ( _isLog )  
              {  
                wsprintf(  
                  buf,  
                  "SYN Scan: About To Scan %u Ports Using %d Thread\r\n",  
                  dword_407090 - _portScanSingle + 1,  
                  _maxThreads);  
                logWriteBuffer(_logFile, buf);  
              }  
            }  
          }  
          else  
          {  
            if ( _isMultiplePort )  
            {  
              printf("Normal Scan: About To Scan %u Ports Using %d Thread\n", _portsTotal, _maxThreads);  
              if ( _isLog )  
              {  
                wsprintf(buf, "Normal Scan: About To Scan %u Ports Using %d Thread\r\n", _portsTotal, _maxThreads);  
                logWriteBuffer(_logFile, buf);  
              }  
            }  
            else  
            {  
              printf(  
                "Normal Scan: About To Scan %u Ports Using %d Thread\n",  
                dword_407090 - _portScanSingle + 1,  
                _maxThreads);  
              if ( _isLog )  
              {  
                wsprintf(  
                  buf,  
                  "Normal Scan: About To Scan %u Ports Using %d Thread\r\n",  
                  dword_407090 - _portScanSingle + 1,  
                  _maxThreads);  
                logWriteBuffer(_logFile, buf);  
              }  
            }  
          }  
        }  
      }  
    }  
    else  
    {  
      if ( isSynScan )  
      {  
        if ( _isMultiplePort )  
        {  
          printf(  
            "SYN Scan: About To Scan %u IP For %u Ports Using %d Thread\n",  
            _endIp - _startIp + 1,  
            _portsTotal,  
            _maxThreads);  
          if ( _isLog )  
          {  
            wsprintf(  
              buf,  
              "SYN Scan: About To Scan %u IP For %u Ports Using %d Thread\r\n",  
              _endIp - _startIp + 1,  
              _portsTotal,  
              _maxThreads);  
            logWriteBuffer(_logFile, buf);  
          }  
        }  
        else  
        {  
          printf(  
            "SYN Scan: About To Scan %u IP For %u Ports Using %d Thread\n",  
            _endIp - _startIp + 1,  
            dword_407090 - _portScanSingle + 1,  
            _maxThreads);  
          if ( _isLog )  
          {  
            wsprintf(  
              buf,  
              "SYN Scan: About To Scan %u IP For %u Ports Using %d Thread\r\n",  
              _endIp - _startIp + 1,  
              dword_407090 - _portScanSingle + 1,  
              _maxThreads);  
            logWriteBuffer(_logFile, buf);  
          }  
        }  
      }  
      else  
      {  
        if ( _isMultiplePort )  
        {  
          printf(  
            "Normal Scan: About To Scan %u IP For %u Ports Using %d Thread\n",  
            _endIp - _startIp + 1,  
            _portsTotal,  
            _maxThreads);  
          if ( _isLog )  
          {  
            wsprintf(  
              buf,  
              "Normal Scan: About To Scan %u IP For %u Ports Using %d Thread\r\n",  
              _endIp - _startIp + 1,  
              _portsTotal,  
              _maxThreads);  
            logWriteBuffer(_logFile, buf);  
          }  
        }  
        else  
        {  
          printf(  
            "Normal Scan: About To Scan %u IP For %u Ports Using %d Thread\n",  
            _endIp - _startIp + 1,  
            dword_407090 - _portScanSingle + 1,  
            _maxThreads);  
          if ( _isLog )  
          {  
            wsprintf(  
              buf,  
              "Normal Scan: About To Scan %u IP For %u Ports Using %d Thread\r\n",  
              _endIp - _startIp + 1,  
              dword_407090 - _portScanSingle + 1,  
              _maxThreads);  
            logWriteBuffer(_logFile, buf);  
          }  
        }  
      }  
    }  
    if ( isSynScan )  
    {  
      ++_threadsUsed;  
      synScan();  
      goto LABEL_147;  
    }  
    v37 = 0;  
    currentIp = _startIp;  
    while ( currentIp <= _endIp )  
    {  
      if ( _isMultiplePort )  
      {  
        portIndex = 0;  
        while ( portIndex < _portsTotal )  
        {  
          lpParameter = malloc(sizeof(DWORD) * 2);  
          if ( lpParameter )  
          {  
            *(DWORD *)lpParameter = currentIp;  
            *((DWORD *)lpParameter + 1) = *((DWORD *)_portsArray + portIndex);  
  
            v17 = CreateThread(0, 0, tcpScanThread, lpParameter, 0, &ThreadId);  
            hObject = v17;  
            if ( v17 )  
            {  
              EnterCriticalSection(&_cs);  
              printf("%u IP Scanned.Taking %d Threads \r", _ipScanned / (unsigned int)_portsTotal, _threadsUsed++);  
              ++count;  
              LeaveCriticalSection(&_cs);  
              CloseHandle(hObject);  
            }  
            if ( _isBreak )  
            {  
              v26 = currentIp + 1;  
              lastPortScan = *((DWORD *)_portsArray + portIndex);  
              v37 = 1;  
              break;  
            }  
            WaitForSingleObject(_semaphore, INFINITE);  
          }  
          ++portIndex;  
        }  
      }  
      else  
      {  
        lpParameter = (LPVOID)(dword_407090 - _portScanSingle + 1);  
        portIndex = _portScanSingle;  
        while ( portIndex <= dword_407090 )  
        {  
          param = malloc(sizeof(DWORD) * 2);  
          if ( param )  
          {  
            *(DWORD *)param = currentIp;  
            *((DWORD *)param + 1) = portIndex;  
            hObject = CreateThread(0, 0, tcpScanThread, (LPVOID)param, 0, &ThreadId);  
            if ( hObject )  
            {  
              EnterCriticalSection(&_cs);  
              if ( _isRangeScan )  
              {  
                if ( !_isSinglePort )  
                  printf("%u Ports Scanned.Taking %d Threads \r", _ipScanned, _threadsUsed);  
              }  
              else  
              {  
                v23 = _ipScanned / (unsigned int)lpParameter;  
                printf("%u IP Scanned.Taking %d Threads \r", _ipScanned / (unsigned int)lpParameter, _threadsUsed);  
              }  
              ++_threadsUsed;  
              ++count;  
              LeaveCriticalSection(&_cs);  
              CloseHandle(hObject);  
            }  
            if ( _isBreak )  
            {  
              if ( _isRangeScan )  
                v26 = currentIp;  
              else  
                v26 = currentIp + 1;  
              lastPortScan = portIndex;  
              v37 = 1;  
              break;  
            }  
            WaitForSingleObject(_semaphore, INFINITE);  
          }  
          ++portIndex;  
        }  
      }  
      if ( v37 )  
        break;  
      ++currentIp;  
    }  
LABEL_147:  
    while ( _threadsUsed )  
    {  
      WaitForSingleObject(_semaphore, INFINITE);  
      EnterCriticalSection(&_cs);  
      printf("%d Threads Are In Process......              \r", _threadsUsed);  
      v29 = ReleaseSemaphore(_semaphore, 1, &previousCount);  
      LeaveCriticalSection(&_cs);  
      if ( !v29 )  
      {  
        v20 = GetLastError();  
        printf("Error Code: %d\n", v20);  
        Sleep(3000);  
        break;  
      }  
      if ( previousCount + 1 != _maxThreads )  
      {  
        Sleep(10);  
        if ( isSynScan )  
          continue;  
        if ( _ipScanned != count )  
          continue;  
      }  
      break;  
    }  
    if ( isSynScan )  
      Sleep(500);  
    if ( !isSynScan )  
    {  
      if ( _isBreak )  
      {  
        wsprintf(  
          lastScan,  
          "%d.%d.%d.%d",  
          (unsigned int)v26 >> 24,  
          ((unsigned int)v26 >> 16) & 0xFF,  
          (unsigned __int16)((WORD)v26 >> 8),  
          (unsigned __int8)v26);  
        printf("Last Scan: %s:%d                \n", &lastScan, lastPortScan);  
        if ( _isLog )  
        {  
          wsprintf(buf, "LastIP Scanned: %s:%d\r\n", &lastScan, lastPortScan);  
          logWriteBuffer(_logFile, buf);  
        }  
      }  
    }  
    v21 = (GetTickCount() - timeStart) / 0x3E8;  
    currentIp = v21;  
    v45 = v21;  
    if ( !v21 )  
      ++v45;  
    v37 = v45 % 0x15180 / 0xE10;  
    hoursElapsed = v45 % 0x15180 / 0xE10;  
    portIndex = v45 % 0x15180 % 0xE10 / 0x3C;  
    minutesElapsed = v45 % 0x15180 % 0xE10 / 0x3C;  
    secondsElapsed = v45 % 0x15180 % 0xE10 % 0x3C;  
    if ( _isBreak )  
    {  
      if ( _isRangeScan )  
      {  
        printf(  
          "Scan %s Complete In %d Hours %d Minutes %d Seconds. Found %u Open Ports\n",  
          startIpAddr,  
          hoursElapsed,  
          minutesElapsed,  
          secondsElapsed,  
          _totalPortsOpen);  
        if ( _isLog )  
        {  
          wsprintf(  
            buf,  
            "Scan %s Complete In %d Hours %d Minutes %d Seconds. Found %u Open Ports\r\n",  
            startIpAddr,  
            hoursElapsed,  
            minutesElapsed,  
            secondsElapsed,  
            _totalPortsOpen);  
          logWriteBuffer(_logFile, buf);  
        }  
      }  
      else  
      {  
        if ( _isSinglePort )  
        {  
          lpParameter = (LPVOID)_ipScanned;  
        }  
        else  
        {  
          if ( _isMultiplePort )  
          {  
            if ( _portsTotal )  
            {  
              lpParameter = (LPVOID)(_ipScanned / (unsigned int)_portsTotal);  
            }  
            else  
            {  
              lpParameter = (LPVOID)_ipScanned;  
            }  
          }  
          else  
          {  
            v22 = dword_407090 - _portScanSingle + 1;  
            lpParameter = (LPVOID)(_ipScanned / v22);  
          }  
        }  
        printf(  
          "Scan %u IPs Complete In %d Hours %d Minutes %d Seconds. Found %u Hosts\n",  
          lpParameter,  
          hoursElapsed,  
          minutesElapsed,  
          secondsElapsed,  
          _totalPortsOpen);  
        if ( _isLog )  
        {  
          wsprintf(  
            buf,  
            "Scan %u IPs Complete In %d Hours %d Minutes %d Seconds. Found %u Hosts\r\n",  
            lpParameter,  
            hoursElapsed,  
            minutesElapsed,  
            secondsElapsed,  
            _totalPortsOpen);  
          logWriteBuffer(_logFile, buf);  
        }  
      }  
    }  
    else  
    {  
      if ( _isRangeScan )  
      {  
        printf(  
          "Scan %s Complete In %d Hours %d Minutes %d Seconds. Found %u Open Ports\n",  
          startIpAddr,  
          hoursElapsed,  
          minutesElapsed,  
          secondsElapsed,  
          _totalPortsOpen);  
        if ( _isLog )  
        {  
          wsprintf(  
            buf,  
            "Scan %s Complete In %d Hours %d Minutes %d Seconds. Found %u Open Ports\r\n",  
            startIpAddr,  
            hoursElapsed,  
            minutesElapsed,  
            secondsElapsed,  
            _totalPortsOpen);  
          logWriteBuffer(_logFile, buf);  
        }  
      }  
      else  
      {  
        printf(  
          "Scan %u IPs Complete In %d Hours %d Minutes %d Seconds. Found %u Hosts\r\n",  
          _endIp - _startIp + 1,  
          hoursElapsed,  
          minutesElapsed,  
          secondsElapsed,  
          _totalPortsOpen);  
        if ( _isLog )  
        {  
          wsprintf(  
            buf,  
            "Scan %u IPs Complete In %d Hours %d Minutes %d Seconds. Found %u Hosts\r\n",  
            _endIp - _startIp + 1,  
            hoursElapsed,  
            minutesElapsed,  
            secondsElapsed,  
            _totalPortsOpen);  
          logWriteBuffer(_logFile, buf);  
        }  
      }  
    }  
    if ( _isLog )  
      logWriteBuffer(_logFile, "-------------------------------------------------------------------------------\r\n\r\n");  
  
__faild:  
  if ( _semaphore )  
      CloseHandle(_semaphore);  
  if ( _s != -1 )  
      closesocket(_s);  
  if ( _portsArray )  
      free(_portsArray);  
  WSACleanup();  
        return 1;  
  
  return 0;  
}  
  
int main(int argc, char **argv)  
{  
    int ret;  
    printf("TCP Port Scanner V1.2 By WinEggDrop\n\n");  
    if ( argc == 4 || argc == 5 || argc == 6 || argc == 7 || argc == 8 || argc == 9 )  
    {  
     if ( SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE) )  
     {  
         if ( InitializeCriticalSectionAndSpinCount(&_cs, 0x80000400) )  
         {  
             int arg = argc;  
             for (int i = 1; i <= 3; i++)  
             {  
                if (!lstrcmpi(argv[argc - i], "/Save"))  
                {  
                    _isLog = TRUE;  
                }  
                else if (!lstrcmpi(argv[argc - i], "/Banner"))  
                {  
                    _isBanner = TRUE;  
                }  
                else if (!lstrcmpi(argv[argc - i], "/HBanner"))  
                {  
                    _isBanner = TRUE;  
                    _isHttp = TRUE;  
                }  
                else if (!_strnicmp(argv[argc - i], "/T", 2))  
                {  
                    _tcpTimeout = atoi(argv[argc - i]+2);  
  
                    if (!_tcpTimeout)  
                    {  
                        printf("Invalid timeout value\n");  
                        return -1;  
                    }  
                }  
                else  
                {  
                    continue;  
                }  
  
                arg--;  
             }  
               
             switch ( arg )  
             {  
             case 4:  
                 startScan(argv[1], argv[2], 0, argv[3], "1");  
                 break;  
             case 5:  
                 if ( lstrcmpi(argv[1], "SYN") )  
                     startScan(argv[1], argv[2], 0, argv[3], argv[4]);  
                 else  
                     startScan(argv[1], argv[2], argv[3], argv[4], "1");  
                 break;  
             case 6:  
                 startScan(argv[1], argv[2], argv[3], argv[4], argv[5]);  
                 break;  
             }  
             DeleteCriticalSection(&_cs);  
             ret = 0;  
         }  
         else  
         {  
             ret = -1;  
         }  
     }  
     else  
     {  
         printf("Could Not Set Up Control Handler\n");  
         ret = -1;  
     }  
 }  
 else  
 {  
     help(argv[0]);  
     ret = -1;  
 }  
  return ret;  
}  