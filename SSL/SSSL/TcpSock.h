#pragma once

typedef void* HSock;
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;

class TcpSock {
public:
    TcpSock() {}
    virtual ~TcpSock() {}
    virtual HSock GetSock() const = 0;
    virtual bool Incoming() = 0;
    virtual HSock Accept(const TcpSock& listenSock) = 0;
    virtual bool Connected() = 0;
    virtual bool Closed() = 0;
    virtual int Send(const unsigned char* pData, size_t cbSize) = 0;
    virtual int Recv(unsigned char* pData, size_t cbSize) = 0;
};
