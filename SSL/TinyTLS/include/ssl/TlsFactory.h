#ifndef _SSLFACTORY_H_INCLUDED_10_28_2017_
#define _SSLFACTORY_H_INCLUDED_10_28_2017_

#include "TlsCallback.h"

class BaseTls;
class TcpSock;
struct CIPHERSET;
struct CERTKEY_INFO;

#include "../../include/ssl/TlsFactory.h"
#include "../../include/ssl/TinyTls.h"

static BaseTls* CreateTls(
    TcpSock& sock,
    const CIPHERSET& cipherSet,
    //CERTKEY_INFO* pCertInfo,
    unsigned int curTimeSec,
    bool isClient,
    TlsCallback callBack,
    void* pUserContext)
{
    return new TinyTls(sock, cipherSet, curTimeSec, isClient, callBack, pUserContext);
}


#endif //_SSLFACTORY_H_INCLUDED_10_28_2017_
