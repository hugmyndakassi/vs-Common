#pragma once

#include <winsock2.h>
#include "ws2tcpip.h"
#include "TcpSock.h"


struct sockaddr;
typedef unsigned int  uint32_t;
typedef unsigned char uint8_t;


static void DumpData(const char* tag, const uint8_t* p, size_t cbSize)
{
 //  DBGMSG("%s:", tag);
 //  for (int i = 0; i < cbSize; i++) {
 //      DBGMSG("%s%02X", (i&15)? " " : "\n    ", p[i]);
 //  }
 //  DBGMSG("\n");
}

class TcpSockWin32: TcpSock
{
 public:
 static inline int   m_LastError  = 0;
 static const u_long Non_Blocking = 1;

 HSock m_hSock      = nullptr;
 bool  m_bConnected = false;


 static HSock TcpSockWin32::CreateListenSock(unsigned int port)
 {
  m_LastError = 0;

  int    ret  = 0;
  SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  for (; sock != INVALID_SOCKET;)
  {
   // Set up the sockaddr structure
   sockaddr_in addr;
   addr.sin_family      = AF_INET;
   addr.sin_addr.s_addr = INADDR_ANY;
   addr.sin_port        = htons(port);

   // Set socket to non-blocking: 0 blocking; 1: non-blocking
   u_long iBlockingMode = Non_Blocking;
   if (ioctlsocket(sock, FIONBIO, &iBlockingMode)) break;

   // Bind the listening socket to address and port based on sockaddr.
   if (bind(sock, (sockaddr*)&addr, sizeof(addr))) break;

   if (listen(sock, 16)) break;

   return reinterpret_cast<HSock>(sock); // Only successful return.
  }

  m_LastError = WSAGetLastError();
  if (sock != INVALID_SOCKET) closesocket(sock);

  return nullptr;
 }

 TcpSockWin32() { }
 TcpSockWin32(HSock sock) { m_hSock = sock; } //, sockaddr& addr, int addrLen);
 TcpSockWin32(uint32_t ip, uint32_t port)
 {
  int         ret;
  sockaddr_in saddr;
  int         len(sizeof(sockaddr));
  addrinfo*   inf = nullptr;
  addrinfo    hints;

  memset(saddr.sin_zero, 0, sizeof(saddr.sin_zero));
  saddr.sin_family           = AF_INET;
  saddr.sin_addr.S_un.S_addr = htonl(ip);
  saddr.sin_port             = htons(443);

  memset(&hints, 0, sizeof(hints));
  hints.ai_family   = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  ret = getaddrinfo("www.cnn.com", "443", &hints, &inf);
  if (ret) ret = WSAGetLastError();


  m_hSock = reinterpret_cast<HSock>(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));

  // Set socket to non-blocking: 0 blocking; 1: non-blocking
  u_long iBlockingMode = Non_Blocking;
  if (ioctlsocket((SOCKET)m_hSock, FIONBIO, &iBlockingMode)) assert(0);

  ret = connect((SOCKET)m_hSock, (const sockaddr*)&saddr, len);
  // ret = connect((SOCKET)m_hSock, inf->ai_addr, inf->ai_addrlen);

  if (ret)
  { // NonBlocking: WSAEWOULDBLOCK 10035
   ret = WSAGetLastError();
  }
 }

 virtual ~TcpSockWin32() { }

 HSock GetSock() const override { return m_hSock; }

 bool TcpSockWin32::Incoming() override
 {
  if (!m_hSock) return false;

  timeval timeout{0, 0};
  struct my_fd
  {
   u_int  fd_count;
   SOCKET fd_sock;
  } rd{1, SOCKET(m_hSock)}, wd(rd), ed(wd);

  switch (select(1, (fd_set*)&rd, (fd_set*)&wd, (fd_set*)&ed, &timeout))
  {
   case 0:
    break;
   case SOCKET_ERROR:
    m_LastError = WSAGetLastError();
    closesocket(SOCKET(m_hSock));
    m_hSock = nullptr;
    break;
   default:
    if (rd.fd_count >= 0) return true;
    break;
  }

  return false;
 }
 //---------------------------------------------------------------------------------------------------
 HSock TcpSockWin32::Accept(const TcpSock& listenSock) override
 {
  sockaddr addr2;
  int      addr2len = sizeof(addr2);
  SOCKET   sock2    = accept((SOCKET)listenSock.GetSock(), &addr2, &addr2len);

  m_hSock = reinterpret_cast<HSock>(sock2);
  return m_hSock;
 }
 //---------------------------------------------------------------------------------------------------
 bool TcpSockWin32::Connected() override
 {
  if (m_bConnected || m_hSock == nullptr) return m_bConnected;
  timeval timeout{0, 0};
  struct my_fd
  {
   u_int  fd_count;
   SOCKET fd_sock;
  } rd{1, (SOCKET)m_hSock}, wd(rd), ed(wd);

  int ret = select(1, (fd_set*)&rd, (fd_set*)&wd, (fd_set*)&ed, &timeout);

  switch (ret)
  {
   case 0:
    break;
   case SOCKET_ERROR:
    closesocket((SOCKET)m_hSock);
    m_hSock      = nullptr;
    m_bConnected = false;
    break;
   default:
    if (!m_bConnected && (rd.fd_count || wd.fd_count)) m_bConnected = true;
    break;
  }

  return m_bConnected;
 }
 //---------------------------------------------------------------------------------------------------
 bool TcpSockWin32::Closed() override { return (m_hSock == nullptr); }
 //---------------------------------------------------------------------------------------------------
 int TcpSockWin32::Send(const uint8_t* pData, size_t cbSize) override
 {
  if (!Connected()) return 0;

  int nSend = 0, ret;
  DumpData("Send", pData, cbSize);
  while (cbSize)
  {
   ret = send((SOCKET)m_hSock, (const char*)pData, (int)cbSize, 0);
   if (ret >= 0)
   {
    nSend  += ret;
    cbSize -= ret;
    pData  += ret;
    if (cbSize) Sleep(5);
    else return nSend;
   }
   else if (ret == SOCKET_ERROR)
   {
    int err = WSAGetLastError();
    if (err == WSAEWOULDBLOCK || err == WSAENOBUFS) Sleep(5); // Must wait until the socket is ready and retry
    else
    {
     Close();
     break;
    }
   }
  }
  return nSend;
 }
 //---------------------------------------------------------------------------------------------------
 int TcpSockWin32::Recv(uint8_t* pData, size_t cbSize) override
 {
  if (!Connected()) return 0;
  timeval timeout{0, 0};
  struct my_fd
  {
   u_int  fd_count;
   SOCKET fd_sock;
  } rd{1, (SOCKET)m_hSock}, wd(rd), ed(wd);

  int ret = select(1, (fd_set*)&rd, (fd_set*)&wd, (fd_set*)&ed, &timeout);
  if (rd.fd_count == 0) return 0; // No data to read

  ret = recv((SOCKET)m_hSock, (char*)pData, (int)cbSize, 0);
  if (ret > 0)
  {
   DumpData("Recv", pData, ret);
   return ret; // received some data.
  }
  else if (ret == SOCKET_ERROR)
  {
   int err = WSAGetLastError();
   if (err == WSAEWOULDBLOCK) return 0; // But 'select' has already reported some data here!
  }

  // Connection lost
  Close();

  return SOCKET_ERROR;
 }
 //---------------------------------------------------------------------------------------------------

 private:
 void Close()
 {
  if (m_hSock)
  {
   closesocket((SOCKET)m_hSock);
   m_hSock = nullptr;
  }
  m_bConnected = false;
 }
};
