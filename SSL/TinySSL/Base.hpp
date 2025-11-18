

//---------------------------------------------------------------------------------------------
struct CBaseSSL
{
#define PRE_MASTER_SECRET_LEN   48
#define MASTER_SECRET_LEN       48
#define CLIENT_RANDOM_LEN       32
#define SERVER_RANDOM_LEN       32

#define CONTENT_HEADER_LEN      5
#define SSL_OVERHEAD            (CONTENT_HEADER_LEN+MD5_SIZE)

typedef enum
{
    SSLSTATE_RESET                  = 0,    // Reset everything and then go to SSLSTATE_INITIALIZED.
    SSLSTATE_INITIALIZED            = 1,    // Just initialized. Nothing happened yet.
    SSLSTATE_UNCONNECTED            = 2,    // The "RESET" state after a successful or failed connection.
    SSLSTATE_TCPCONNECTED           = 3,    // Application tells us TCP connected. This triggers handshake.
    SSLSTATE_HANDSHAKE_BEGIN        = 4,    // Initialize HandShake & goto SSLSTATE_CLIENT_HELLO

    SSLSTATE_HELLO_REQUEST          = 7,    // Initiate a server hello request message
    SSLSTATE_CLIENT_HELLO           = 8,    // Send out ClientHello & goto SSLSTATE_SERVER_HELLO
    SSLSTATE_CLIENT_CERTREQUEST     = 9,    // Server can set nInXData = non-zero to request client certificate.

    SSLSTATE_SERVER_HELLO           = 16,   // Wait ServerHello, if reuse SessionID, goto SSLSTATE_SERVER_FINISH1, else goto SSLSTATE_SERVER_HELLO_DONE
    SSLSTATE_SERVER_CERTIFICATE     = 17,   // Wait Server Certificate, then go to SSLSTATE_SERVER_HELLO_DONE
    SSLSTATE_SERVER_CERTREQUEST     = 18,   // Certificate request received from server, Wait ServerHelloDone & goto SSLSTATE_CERTIFICATE_REQUEST
    SSLSTATE_SERVER_HELLO_DONE      = 19,   // Wait ServerHelloDone & goto SSLSTATE_CERTIFICATE_VERIFY.

    SSLSTATE_CERTIFICATE_REQUEST    = 20,   // Server asked the client to supply a certificate. Go to SSLSTATE_CERTIFICATE_REQUESTING to tell application.
    SSLSTATE_CERTIFICATE_REQUESTING = 21,   // Application asked to supply a client certificate and goto SSLSTATE_CERTIFICATE_SUPPLIED, or fall to SSLSTATE_CERTIFICATE_NOTGIVEN
    SSLSTATE_CERTIFICATE_NOTGIVEN   = 22,   // In SSLSTATE_CERTIFICATE_REQUESTING, App fails to give us certificate. Goto SSLSTATE_ABORTING.
    SSLSTATE_CERTIFICATE_SUPPLIED   = 23,   // In SSLSTATE_CERTIFICATE_REQUESTING, App supplied it and set SSLSTATE_CERTIFICATE_SUPPLIED. Go to SSLSTATE_CERTIFICATE_VERIFY

    SSLSTATE_CERTIFICATE_VERIFY     = 24,   // Verify server certificate and goto SSLSTATE_CERTIFICATE_VERIFIED
    SSLSTATE_CERTIFICATE_VERIFIED   = 25,   // Certificate verified. Go to SSLSTATE_CLIENT_KEYEXCHANGE.
    SSLSTATE_CERTIFICATE_ACCEPTING  = 26,   // Wait for application to accept questionable certificate. nOutXData carries the HCERT. Default goes to SSLSTATE_CERTIFICATE_REJECTED
    SSLSTATE_CERTIFICATE_REJECTED   = 27,   // Bad certificate rejected. Goto SSLSTATE_ABORTING.
    SSLSTATE_CERTIFICATE_EXPIRED    = 28,   // Certificate expired. Goto SSLSTATE_ABORTING.
    SSLSTATE_CERTIFICATE_ACCEPTED   = 29,   // Certificate accepted by App, goto SSLSTATE_CLIENT_KEYEXCHANGE, or SSLSTATE_CLIENT_CERTIFICATE first

    SSLSTATE_CLIENT_CERTIFICATE     = 32,   // Send the client certificate message to server and go to SSLSTATE_CLIENT_KEYEXCHANGE
    SSLSTATE_CLIENT_KEYEXCHANGE     = 33,   // Send ClientKeyExchange & goto SSLSTATE_CLIENT_FINISH1, or SSLSTATE_CLIENT_VALIDATE first
    SSLSTATE_CLIENT_VALIDATE        = 34,   // Send Client certificate verify message & goto SSLSTATE_CLIENT_FINISH1

    SSLSTATE_SERVER_FINISH1         = 40,   // Wait for ServerFinish & goto SSLSTATE_CLIENT_FINISH2.
    SSLSTATE_CLIENT_FINISH1         = 41,   // Send ChangeCipher, Finish & goto SSLSTATE_SERVER_FINISH2
    SSLSTATE_CLIENT_FINISH2         = 42,   // Send ChangeCipher, Finish & goto SSLSTATE_HANDSHAKE_DONE
    SSLSTATE_SERVER_FINISH2         = 43,   // Wait for ServerFinish & goto SSLSTATE_HANDSHAKE_DONE.
    SSLSTATE_HANDSHAKE_DONE         = 48,   // Verify every thing OK & goto SSLSTATE_CONNECTED, else

    SSLSTATE_CONNECTED              = 64,   // We can now exchange application data encrypted.
    SSLSTATE_DISCONNECT             = 66,   // App tells us to initiate a disconnect sequence.
    SSLSTATE_DISCONNECTING          = 67,   // We were told by the server to disconnect. Tell App to disconnect
    SSLSTATE_DISCONNECTED           = 68,   // App tells us TCP disconnected. Cleanup and goto SSLSTATE_UNCONNECTED
    SSLSTATE_ABORT                  = 70,   // We fall into a fatal error processing incoming message. So bail out.
    SSLSTATE_ABORTING               = 71,   // Notify server we are aborting a failed connection, then goto SSLSTATE_ABORTED
    SSLSTATE_ABORTED                = 72,   // Failed connection aborted. App disconnect TCP and goto SSLSTATE_DISCONNECTED
    SSLSTATE_ERROR                  = -1    // Any other errors.
} SSL_STATE;


typedef enum
{
    SSL_OK                  = 0,
    SSL_RESULT_INVALID      = 1,
    SSL_RESULT_NOT_APPLY    = 2,
    SSL_ERROR_GENERIC       = -1,
    SSL_ERROR_PARSE         = -2,
    SSL_ERROR_TIMEOUT       = -3,
    SSL_ERROR_MEMORY        = -4,
    SSL_ERROR_NOTREADY      = -5,
    SSL_ERROR_CERTIFICATE_EXISTS = -6,
    SSL_ERROR_CERTIFICATE_BAD   = -7,
    SSL_ERROR_BUFFER_FULL   = -8,
    SSL_ERROR_LIMIT32       = 0xFFFF0000    //Forcing 32 bits int for enum
} SSL_RESULT;

#define MD5 CTX
#define SHA CTX


#define ISCLIENT    1
#define ISSERVER    0


#define SSL_VERSION_MAJOR   3
#define SSL_VERSION_MINOR   0
#define SSL_VERSION_MINOR1  1


// The following defines SSL 3.0 content types
#define CONTENT_CHANGECIPHERSPEC    0x14
#define CONTENT_ALERT               0x15
#define CONTENT_HANDSHAKE           0x16
#define CONTENT_APPLICATION_DATA    0x17


//The following defines SSL 3.0/TLS 1.0 Handshake message types
#define MSG_HELLO_REQUEST           0x00
#define MSG_CLIENT_HELLO            0x01
#define MSG_SERVER_HELLO            0x02
#define MSG_CERTIFICATE             0x0B
#define MSG_SERVER_KEY_EXCHANGE     0x0C
#define MSG_CERTIFICATE_REQUEST     0x0D
#define MSG_SERVER_HELLO_DONE       0x0E
#define MSG_CERTIFICATE_VERIFY      0x0F
#define MSG_CLIENT_KEY_EXCHANGE     0x10
#define MSG_FINISHED                0x14

//The followings are used for secured re-negotiation. See RFC5746.
#define MSG_EXTENTION               0xFF
#define MSG_EXTENTION_RENEGOTIATION 0x01

//This is only used in CONTENT_CHANGECIPHERSPEC content type
#define MSG_CHANGE_CIPHER_SPEC      0x01


//The following defines SSL 3.0/TLS 1.0 ALERT message types
//1st byte of ALERT message indicates whether it is a warning or fatal.
#define ALERT_WARNING               0x01
#define ALERT_FATAL                 0x02
//2nd byte of ALERT message indicates the nature of the alert.
#define ALERT_NOTIFY_CLOSE          0x00
#define ALERT_MESSAGE_UNEXPECTED    0x0A
#define ALERT_RECORD_MAC_BAD        0x14
#define ALERT_DECRYPTION_FAILED     0x15
#define ALERT_RECORD_OVERFLOW       0x16
#define ALERT_DECOMPRESSION_FAILED  0x1E
#define ALERT_HANDSHAKE_FAILED      0x28
#define ALERT_CERTIFICATE_BAD       0x2A
#define ALERT_CERTIFICATE_UNSUPPORTED   0x2B
#define ALERT_CERTIFICATE_REVOKED   0x2C
#define ALERT_CERTIFICATE_EXPIRED   0x2D
#define ALERT_CERTIFICATE_UNKNOWN   0x2E
#define ALERT_PARAMETER_ILLEGAL     0x2F
#define ALERT_CA_UNKNOWN            0x30
#define ALERT_ACCESS_DENIED         0x31
#define ALERT_DECODE_ERROR          0x32
#define ALERT_DECRYPT_ERROR         0x33
#define ALERT_EXPORT_RESTRICTION    0x3C
#define ALERT_PROTOCOL_VERSION      0x46
#define ALERT_SECURITY_INSUFFICIENT 0x47
#define ALERT_INTERNAL_ERROR        0x50
#define ALERT_USER_CANCELED         0x5A
#define ALERT_NO_NEGOTIATION        0x64


#define PAD1_BYTE                   0x36
#define PAD2_BYTE                   0x5C
#define PADSIZE_MD5                 0x30
#define PADSIZE_SHA                 0x28
#define MD5_SIZE                    16
#define SHA1_SIZE                   20

//Do not change these values. They are defined by SSL 3.0.
#define CLIENT_RANDOM_SIZE      32
#define SERVER_RANDOM_SIZE      32
#define MASTER_SECRET_LEN       48
#define PRE_MASTER_SECRET_LEN   48

#define MAC_SECRET_LEN          16
#define WRITE_KEY_LEN           16

#define CHALLENGE_LEN           16  //Challenge length of V.20 ClientHello
#define TLS_VERIFY_LEN          12  //Verify block length for TLS 1.0 and later.

typedef enum
{
    CIPHER_NOTSET           = 0,
    CIPHER_RSA_RC4_40_MD5   = 3,
    CIPHER_RSA_RC4_128_MD5  = 4,
    CIPHER_RSA_RC4_128_SHA  = 5
} SSL_CIPHER;

typedef struct CTX {
    uint    data[24];
} CTX;

typedef union EBLOCK {
    uchar       encryptBlock[256];  //Max RSA key is 2048 bits = 256 bytes
    struct {
        CTX     md5Hash;
        CTX     sha1Hash;
        uchar   md5Digest[MD5_SIZE];
        uchar   sha1Digest[SHA1_SIZE];
    };
} EBLOCK;

typedef struct SSL* HSSL;
typedef struct CIPHERSET CIPHERSET;

#define     IN      //Input parameter
#define     OUT     //Output parameter
#define     MDD     //Modifiable parameter

typedef union {
    void *          ptr;
    unsigned int    data;
} XDATA;


typedef struct CERTKEY_INFO
{
    struct CERTKEY_INFO*    pPrev;
    struct CERTKEY_INFO*    pNext;
    uint            nKeyLengthBits;
    const uchar*    pCertificate;
    const uchar*    pPublicKey;
    const uchar*    pPrivateKey;
} CERTKEY_INFO;


typedef struct SSL_PARAMS
{
    MDD SSL_STATE               eState;         //State of the SSL engine.
    IN  unsigned int            nUnixTime;      //Seconds since EPOCH, Jan. 01, 1970 12:00am UTC
    IN  XDATA                   nInXData;       //Undefined data application sent to SSL
    OUT XDATA                   nOutXData;      //Undefined data SSL engine send to caller
    MDD const unsigned char*    pNetInData;     //Incoming network data pointer
    MDD unsigned int            nNetInSize;     //Incoming network data size.
    IN  const unsigned char*    pAppInData;     //Application data sent into SSL and to server
    MDD unsigned int            nAppInSize;     //Size of Application data into SSL then server
    OUT const unsigned char*    pNetOutData;    //Outgoing network data pointer
    OUT unsigned int            nNetOutSize;    //Outgoing network data size
    MDD unsigned char*          pAppOutData;    //Buffer to receive Application Data which came from server
    MDD unsigned int            nAppOutSize;    //Buffer size, and size of data sent to application, from server
} SSL_PARAMS;


typedef void* (*SSL_MALLOC)(unsigned int nSize);
typedef void  (*SSL_FREE)(void* pMemBlock);

//Application provided Pseudo Random Number Generator (PRNG) function.
//Application must initialize and seed the PRNG first.
typedef unsigned int (*SSL_RANDOM)();

//The pUserData will be interpreted as a HSSL, SSL Handle.
typedef SSL_RESULT (*SSL_CALLBACK)(SSL_PARAMS* pParam, HSSL pUserData);

//---------------------------------------------------------------------------------------------
    SSL_STATE   eState;
    SSL_CIPHER  ePendingCipher;
    SSL_CIPHER  eClientCipher;
    SSL_CIPHER  eServerCipher;
    uint    serverMsgOff;
    uint    serverMsgLen;
    uint    nNetOutSize;
    uint    nAppOutSize;
    uint    clientSequenceL;    //Low DWORD. Sequence Number is 64 bits
    uint    clientSequenceH;    //High DWORD.Sequence number is 64 bits
    uint    serverSequenceL;    //Low DWORD. Sequence Number is 64 bits
    uint    serverSequenceH;    //High DWORD.Sequence number is 64 bits

    SSL_RESULT      eLastError;         //Last processing error. Used by functions
    struct CERT*    pServerCert;
    const CERTKEY_INFO* pCertKey;

    uint    nStartTime;         //These times are UNIX TIME. i.e. number of
    uint    nCurrentTime;       //seconds since EPOCH, 00:00AM 01/01/1970 UTC

    //SSL_MALLOC  pMallocFunc;
    //SSL_FREE    pFreeFunc;
    //SSL_RANDOM  pRandomFunc;
    uint    nSessionIDLen;

    uchar   sessionID[32];
    uchar   clientRandom[CLIENT_RANDOM_SIZE];
    uchar   serverRandom[SERVER_RANDOM_SIZE];

    uchar   preMasterSecret[PRE_MASTER_SECRET_LEN];
    uchar   masterSecret[MASTER_SECRET_LEN];
    uchar   clientMacSecret[20];
    uchar   serverMacSecret[20];
    uchar   clientWriteKey[16];
    uchar   serverWriteKey[16];

    RC4         clientCipher;
    RC4         serverCipher;
    CTX         md5Ctx;
    CTX         sha1Ctx;

    uchar*  pTemp;      //These three are temporary variables
    uint    nTemp1;     //To be used in any callback functions
    uint    nTemp2;     //Do not rely on them being persisted.

    uchar*  serverMsg;
    uchar*  appoutMsg;
    uchar   netoutMsg[8192];
    uchar   clientVerify[36];
    uchar   serverVerify[36];

    struct CERT*    pMidCerts;
//---------------------------------------------------------------------------------------------
//Global data declarations
static inline uint nSSLInstanceCount = 0;
static inline SSL_MALLOC  gfMalloc = NULL; //Memory allocation function. Must NOT be NULL.
static inline SSL_FREE    gfFree   = NULL; //Memory deallocate function. Must NOT be NULL.
static inline SSL_RANDOM  gfRandom = NULL; //Pseudo Random Number Generator function. Must NOT be NULL.

static inline CIPHERSET* gpCipherSet = NULL;

static inline uint gSvrMsgSize = 0 ;
static inline uint gAppMsgSize = 0 ;

//Used in SSL 3.0
static const inline uchar SENDER_CLIENT[] = "CLNT";
static const inline uchar SENDER_SERVER[] = "SRVR";

//Used in SSL 3.1 / TLS 1.0 and after.
static const inline char   CLIENT_LABEL[] = "client finished";
static const inline char   SERVER_LABEL[] = "server finished";


static const inline uchar PAD1[PADSIZE_MD5] = //Size is MAX(PADSIZE_MD5, PADSIZE_SHA)
{
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
};

static const inline uchar PAD2[PADSIZE_MD5] = //Size is MAX(PADSIZE_MD5, PADSIZE_SHA)
{
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C
};

/******************************************************************************
* Function:     Int2Byte
*
* Description:  Native endian 4 bytes integers to network order bytes.
*
* Returns:      None
******************************************************************************/
static void Int2Byte(const uint* pIn, uchar* pOut, uint nLen)
{
    for ( ; nLen--; )
    {
        uint    val = *pIn++;
        *pOut++ = (uchar)(val>>24);
        *pOut++ = (uchar)(val>>16);
        *pOut++ = (uchar)(val>>8);
        *pOut++ = (uchar)(val);
    }
}


/******************************************************************************
* Function:     Byte2Int
*
* Description:  Network order bytes to native endian 4 bytes integers.
*
* Returns:      None
******************************************************************************/
static void Byte2Int(const uchar* pIn, uint* pOut, uint nLen)
{
    for ( ; nLen--; )
    {
        uint    val;
        
        val =            (*pIn++);
        val = (val<<8) + (*pIn++);
        val = (val<<8) + (*pIn++);
        val = (val<<8) + (*pIn++);
        *pOut++ = val;
    }
}


/******************************************************************************
* Function:     Int2LByte
*
* Description:  Native endian 4 bytes integers to little endian order bytes.
*
* Returns:      None
******************************************************************************/
static void Int2LByte(const uint* pIn, uchar* pOut, uint nLen)
{
    for ( ; nLen--; )
    {
        uint    val = *pIn++;
        *pOut++ = (uchar)(val);
        *pOut++ = (uchar)(val>>8);
        *pOut++ = (uchar)(val>>16);
        *pOut++ = (uchar)(val>>24);
    }
}


/******************************************************************************
* Function:     LByte2Int
*
* Description:  Little endian order bytes to native endian 4 bytes integers.
*
* Returns:      None
******************************************************************************/
static void LByte2Int(const uchar* pIn, uint* pOut, uint nLen)
{
    for ( ; nLen--; )
    {
        uint    val;
        
        val  = ((uint)(*pIn++));
        val += ((uint)(*pIn++))<<8;
        val += ((uint)(*pIn++))<<16;
        val += ((uint)(*pIn++))<<24;
        *pOut++ = val;
    }
}

//---------------------------------------------------------------------------------------------------

/******************************************************************************
* Function:     CalcMasterSecret
*
* Description:  Calculate Master secret using SSL 3.0
*
* Returns:      None.
******************************************************************************/
void CalcMasterSecret
(
    uchar       theMasterSecret[MASTER_SECRET_LEN],
    const uchar preMasterSecret[PRE_MASTER_SECRET_LEN],
    const uchar pClientRandom[CLIENT_RANDOM_LEN],
    const uchar pServerRandom[SERVER_RANDOM_LEN]
)
{
    MD5     md5a, md5b;
    SHA     sha1;
    uchar   sha1Digest[SHA1_SIZE];
    const CIPHER* pMd5 = &(gpCipherSet->md5);
    const CIPHER* pSha = &(gpCipherSet->sha1);

    pMd5->Init(&md5a, pMd5->pIData);
    pMd5->Input(&md5a, preMasterSecret, PRE_MASTER_SECRET_LEN);

    md5b = md5a;
    pSha->Init(&sha1, pSha->pIData);
    pSha->Input(&sha1, (uchar*)"A", 1);
    pSha->Input(&sha1, preMasterSecret, PRE_MASTER_SECRET_LEN);
    pSha->Input(&sha1, pClientRandom, CLIENT_RANDOM_LEN);
    pSha->Input(&sha1, pServerRandom, SERVER_RANDOM_LEN);
    pSha->Digest(&sha1, sha1Digest);
    pMd5->Input(&md5b, sha1Digest, sizeof(sha1Digest));
    pMd5->Digest(&md5b, &(theMasterSecret[0]));

    md5b = md5a;
    pSha->Init(&sha1, pSha->pIData);
    pSha->Input(&sha1, (uchar*)"BB", 2);
    pSha->Input(&sha1, preMasterSecret, PRE_MASTER_SECRET_LEN);
    pSha->Input(&sha1, pClientRandom, CLIENT_RANDOM_LEN);
    pSha->Input(&sha1, pServerRandom, SERVER_RANDOM_LEN);
    pSha->Digest(&sha1, sha1Digest);
    pMd5->Input(&md5b, sha1Digest, sizeof(sha1Digest));
    pMd5->Digest(&md5b, &(theMasterSecret[MD5_SIZE]));

    md5b = md5a;
    pSha->Init(&sha1, pSha->pIData);
    pSha->Input(&sha1, (uchar*)"CCC", 3);
    pSha->Input(&sha1, preMasterSecret, PRE_MASTER_SECRET_LEN);
    pSha->Input(&sha1, pClientRandom, CLIENT_RANDOM_LEN);
    pSha->Input(&sha1, pServerRandom, SERVER_RANDOM_LEN);
    pSha->Digest(&sha1, sha1Digest);
    pMd5->Input(&md5b, sha1Digest, sizeof(sha1Digest));
    pMd5->Digest(&md5b, &(theMasterSecret[MD5_SIZE*2]));
}


/******************************************************************************
* Function:     CalcKeysFromMaster
*
* Description:  Calculate keys from master secret using SSL 3.0
*               This function MUST be called twice causing redundant calculation.
*               Called upon the change cipher spec messages, once for client
*               and another time for server. The part not expected to be changed
*               must be preserved.
*
* Returns:      None.
******************************************************************************/
void CalcKeysFromMaster
(
    struct SSL* pSSL,
    uint        bIsClient
)
{
    MD5     md5a, md5b;
    SHA     sha1;
    uchar       shaDigest[SHA1_SIZE];
    uchar       macSecret[SHA1_SIZE];
    uchar       writeKey[16];
    const CIPHER*   pMd5 = &(gpCipherSet->md5);
    const CIPHER*   pSha = &(gpCipherSet->sha1);

    //Preserve the part that is not expected to be changed yet.
    if (CIPHER_RSA_RC4_128_SHA  == pSSL->ePendingCipher)
    if (bIsClient)
    {
        memcpy(macSecret, pSSL->serverMacSecret, sizeof(macSecret));
        memcpy(writeKey, pSSL->serverWriteKey, sizeof(writeKey));
    }
    else
    {
        memcpy(macSecret, pSSL->clientMacSecret, sizeof(macSecret));
        memcpy(writeKey, pSSL->clientWriteKey, sizeof(writeKey));
    }

    if ((CIPHER_RSA_RC4_40_MD5  == pSSL->ePendingCipher) ||
        (CIPHER_RSA_RC4_128_MD5 == pSSL->ePendingCipher) ||
        (CIPHER_RSA_RC4_128_SHA  == pSSL->ePendingCipher) )
    {
        pMd5->Init(&md5a, pMd5->pIData);
        pMd5->Input(&md5a, pSSL->masterSecret, sizeof(pSSL->masterSecret));

        //We need to generate a total key block of 64 bytes. Each round of
        //MD5 generates 16 bytes. They are assigned to ClientWriteMacSecret,
        //ServerWriteMacSecret,ClientWriteKey,ServerWriteKey,ClientWriteIV,
        //ServerWriteIV, respectively. Each is 16 bytes except no WriteIV.

        if (bIsClient || (CIPHER_RSA_RC4_128_SHA  == pSSL->ePendingCipher))
        {
        //First round of MD5 is assigned to ClientWriteMacSecret
        md5b = md5a;
        pSha->Init(&sha1, pSha->pIData);
        pSha->Input(&sha1, (uchar*)"A", 1);
        pSha->Input(&sha1, pSSL->masterSecret, sizeof(pSSL->masterSecret));
        pSha->Input(&sha1, pSSL->serverRandom, sizeof(pSSL->serverRandom));
        pSha->Input(&sha1, pSSL->clientRandom, sizeof(pSSL->clientRandom));
        pSha->Digest(&sha1, shaDigest);
        pMd5->Input(&md5b, shaDigest, sizeof(shaDigest));
        pMd5->Digest(&md5b, pSSL->clientMacSecret);
        }

        if (!bIsClient || (CIPHER_RSA_RC4_128_SHA  == pSSL->ePendingCipher))
        {
        //Second round of MD5 is assigned to ServerWriteMacSecret
        md5b = md5a;
        pSha->Init(&sha1, pSha->pIData);
        pSha->Input(&sha1, (uchar*)"BB", 2);
        pSha->Input(&sha1, pSSL->masterSecret, sizeof(pSSL->masterSecret));
        pSha->Input(&sha1, pSSL->serverRandom, sizeof(pSSL->serverRandom));
        pSha->Input(&sha1, pSSL->clientRandom, sizeof(pSSL->clientRandom));
        pSha->Digest(&sha1, shaDigest);
        pMd5->Input(&md5b, shaDigest, sizeof(shaDigest));
        pMd5->Digest(&md5b, pSSL->serverMacSecret);
        }

        //Third round of MD5 is assigned to ClientWriteKey, or ServerWriteKey, too
        md5b = md5a;
        pSha->Init(&sha1, pSha->pIData);
        pSha->Input(&sha1, (uchar*)"CCC", 3);
        pSha->Input(&sha1, pSSL->masterSecret, sizeof(pSSL->masterSecret));
        pSha->Input(&sha1, pSSL->serverRandom, sizeof(pSSL->serverRandom));
        pSha->Input(&sha1, pSSL->clientRandom, sizeof(pSSL->clientRandom));
        pSha->Digest(&sha1, shaDigest);
        pMd5->Input(&md5b, shaDigest, sizeof(shaDigest));
    }
    if ((CIPHER_RSA_RC4_128_MD5 == pSSL->ePendingCipher) ||
        (CIPHER_RSA_RC4_128_SHA == pSSL->ePendingCipher))
    {
        if (bIsClient || (CIPHER_RSA_RC4_128_SHA  == pSSL->ePendingCipher))
        {
        //Output of third round of MD5
        pMd5->Digest(&md5b, pSSL->clientWriteKey);
        }

        if (!bIsClient || (CIPHER_RSA_RC4_128_SHA  == pSSL->ePendingCipher))
        {
        //Fourth round of MD5 is assigned to ServerWriteKey
        md5b = md5a;
        pSha->Init(&sha1, pSha->pIData);
        pSha->Input(&sha1, (uchar*)"DDDD", 4);
        pSha->Input(&sha1, pSSL->masterSecret, sizeof(pSSL->masterSecret));
        pSha->Input(&sha1, pSSL->serverRandom, sizeof(pSSL->serverRandom));
        pSha->Input(&sha1, pSSL->clientRandom, sizeof(pSSL->clientRandom));
        pSha->Digest(&sha1, shaDigest);
        pMd5->Input(&md5b, shaDigest, sizeof(shaDigest));
        pMd5->Digest(&md5b, pSSL->serverWriteKey);
        }

        if (CIPHER_RSA_RC4_128_SHA  == pSSL->ePendingCipher)
        {
        //We need a Fifth round of MD5, as client and server MAC secret is each 20 bytes.
        md5b = md5a;
        pSha->Init(&sha1, pSha->pIData);
        pSha->Input(&sha1, (uchar*)"EEEEE", 5);
        pSha->Input(&sha1, pSSL->masterSecret, sizeof(pSSL->masterSecret));
        pSha->Input(&sha1, pSSL->serverRandom, sizeof(pSSL->serverRandom));
        pSha->Input(&sha1, pSSL->clientRandom, sizeof(pSSL->clientRandom));
        pSha->Digest(&sha1, shaDigest);
        pMd5->Input(&md5b, shaDigest, sizeof(shaDigest));

        memcpy(&(pSSL->clientMacSecret[16]), &(pSSL->serverMacSecret[0]), 4);
        memcpy(&(shaDigest[0]), &(pSSL->serverMacSecret[4]), 12);
        memcpy(&(shaDigest[12]), &(pSSL->clientWriteKey[0]), 8);
        memcpy(pSSL->serverMacSecret, shaDigest, 20);
        memcpy(&(pSSL->clientWriteKey[0]), &(pSSL->clientWriteKey[8]), 8);
        memcpy(&(pSSL->clientWriteKey[8]), &(pSSL->serverWriteKey[0]), 8);
        memcpy(&(pSSL->serverWriteKey[0]), &(pSSL->serverWriteKey[8]), 8);

        pMd5->Digest(&md5b, shaDigest);
        memcpy(&(pSSL->serverWriteKey[8]), shaDigest, 8);
        }
    }
    else if (CIPHER_RSA_RC4_40_MD5 == pSSL->ePendingCipher)
    {
        union {
            uchar   digest[MD5_SIZE];
            struct  {
                uchar   seedClientKey[5];   //40 bits
                uchar   seedServerKey[5];   //40 bits
                uchar   unUsed[6];
            }       keySeeds;
        }       theSeed;

        //Output of third round MD5 is 16 bytes, first 5 bytes used to seed generation
        //of ClientWriteKey, the next 5 bytes for seeding generation of ServerWriteKey.
        pMd5->Digest(&md5b, theSeed.digest);

        if (bIsClient)
        {
        pMd5->Init(&md5b, pMd5->pIData);
        pMd5->Input(&md5b, theSeed.keySeeds.seedClientKey, sizeof(theSeed.keySeeds.seedClientKey));
        pMd5->Input(&md5b, pSSL->clientRandom, sizeof(pSSL->clientRandom));
        pMd5->Input(&md5b, pSSL->serverRandom, sizeof(pSSL->serverRandom));

        //Output the ClientWriteKey, i.e., MD5 hash of the seed, clientRandom and ServerRandom.
        pMd5->Digest(&md5b, pSSL->clientWriteKey);
        }
        else
        {
        //Now generate the ServerWriteKey.
        pMd5->Init(&md5b, pMd5->pIData);
        pMd5->Input(&md5b, theSeed.keySeeds.seedServerKey, sizeof(theSeed.keySeeds.seedClientKey));
        pMd5->Input(&md5b, pSSL->serverRandom, sizeof(pSSL->serverRandom));
        pMd5->Input(&md5b, pSSL->clientRandom, sizeof(pSSL->clientRandom));

        //Output the ClientWriteKey, i.e., MD5 hash of the seed, clientRandom and ServerRandom.
        pMd5->Digest(&md5b, pSSL->serverWriteKey);
        }
    }
    else
    {
        // Unsupported Cipher Suite.
    }

    //Recover the part that is not expected to be changed yet.
    if (CIPHER_RSA_RC4_128_SHA  == pSSL->ePendingCipher)
    if (bIsClient)
    {
        memcpy(pSSL->serverMacSecret, macSecret, sizeof(macSecret));
        memcpy(pSSL->serverWriteKey, writeKey, sizeof(writeKey));
    }
    else
    {
        memcpy(pSSL->clientMacSecret, macSecret, sizeof(macSecret));
        memcpy(pSSL->clientWriteKey, writeKey, sizeof(writeKey));
    }
}


/******************************************************************************
* Function:     CalcMasterSecret1
*
* Description:  Calculate Master secret using SSL 3.1 (TLS 1.0).
*
* Returns:      None.
******************************************************************************/
void CalcMasterSecret1
(
    uchar       theMasterSecret[MASTER_SECRET_LEN],
    const uchar preMasterSecret[PRE_MASTER_SECRET_LEN],
    const uchar pClientRandom[CLIENT_RANDOM_LEN],
    const uchar pServerRandom[SERVER_RANDOM_LEN]
)
{
    int         i;
    uchar       md5Block[BLOCK_LEN];
    uchar       shaBlock[BLOCK_LEN];
    const char* pLabel = "master secret";
    const int   nLSize = strlen(pLabel);
    VDATA       dataBlocks[6] = {
        {NULL,  0},
        {NULL,  0},
        {(const uchar*)pLabel, nLSize},
        {pClientRandom, CLIENT_RANDOM_LEN},
        {pServerRandom, SERVER_RANDOM_LEN},
        {NULL,  0}
        };
    HMAC        hMAC;

    memset(md5Block, 0, sizeof(md5Block));
    memset(shaBlock, 0, sizeof(shaBlock));

    dataBlocks[1].pData = NULL;
    dataBlocks[1].nSize = 0;

    dataBlocks[0].pData = preMasterSecret;
    dataBlocks[0].nSize = ((PRE_MASTER_SECRET_LEN+1)>>1);
    HMAC_InitMD5(&hMAC, md5Block, &(dataBlocks[0]));

    dataBlocks[0].pData = &(preMasterSecret[PRE_MASTER_SECRET_LEN>>1]);
    dataBlocks[0].nSize = ((PRE_MASTER_SECRET_LEN+1)>>1);
    HMAC_InitSHA1(&hMAC, shaBlock, &(dataBlocks[0]));


    //First calculate P_MD5. See http://www.ietf.org/rfc/rfc2246.txt and rfc4104.txt.

    //First calculate A(1), A(2), A(3) for P_MD5 and P_SHA1

    //Calculate A(1);
    HMAC_MD5 (&hMAC, &(md5Block[MD5_SIZE*0]), &(dataBlocks[2]));
    HMAC_SHA1(&hMAC, &(shaBlock[SHA1_SIZE*0]), &(dataBlocks[2]));

    //Calculate A(2);
    dataBlocks[0].pData = &(md5Block[MD5_SIZE*0]);
    dataBlocks[0].nSize = MD5_SIZE;
    HMAC_MD5 (&hMAC, &(md5Block[MD5_SIZE*1]), &(dataBlocks[0]));
    dataBlocks[0].pData = &(shaBlock[SHA1_SIZE*0]);
    dataBlocks[0].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMAC, &(shaBlock[SHA1_SIZE*1]), &(dataBlocks[0]));

    //Calculate A(3);
    dataBlocks[0].pData = &(md5Block[MD5_SIZE*1]);
    dataBlocks[0].nSize = MD5_SIZE;
    HMAC_MD5 (&hMAC, &(md5Block[MD5_SIZE*2]), &(dataBlocks[0]));
    dataBlocks[0].pData = &(shaBlock[SHA1_SIZE*1]);
    dataBlocks[0].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMAC, &(shaBlock[SHA1_SIZE*2]), &(dataBlocks[0]));

    //Calculate HMAC_MD5(1) and HMAC_SHA1(1)
    dataBlocks[1].pData = &(md5Block[MD5_SIZE*0]);
    dataBlocks[1].nSize = MD5_SIZE;
    HMAC_MD5 (&hMAC, &(md5Block[MD5_SIZE*0]), &(dataBlocks[1]));
    dataBlocks[1].pData = &(shaBlock[SHA1_SIZE*0]);
    dataBlocks[1].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMAC, &(shaBlock[SHA1_SIZE*0]), &(dataBlocks[1]));

    //Calculate HMAC_MD5(2) and HMAC_SHA1(2)
    dataBlocks[1].pData = &(md5Block[MD5_SIZE*1]);
    dataBlocks[1].nSize = MD5_SIZE;
    HMAC_MD5 (&hMAC, &(md5Block[MD5_SIZE*1]), &(dataBlocks[1]));
    dataBlocks[1].pData = &(shaBlock[SHA1_SIZE*1]);
    dataBlocks[1].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMAC, &(shaBlock[SHA1_SIZE*1]), &(dataBlocks[1]));

    //Calculate HMAC_MD5(3) and HMAC_SHA1(3)
    dataBlocks[1].pData = &(md5Block[MD5_SIZE*2]);
    dataBlocks[1].nSize = MD5_SIZE;
    HMAC_MD5 (&hMAC, &(md5Block[MD5_SIZE*2]), &(dataBlocks[1]));
    dataBlocks[1].pData = &(shaBlock[SHA1_SIZE*2]);
    dataBlocks[1].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMAC, &(shaBlock[SHA1_SIZE*2]), &(dataBlocks[1]));

    //Finally calculate the Master Secret from P_MD5 and P_SHA1.
    for (i=0; i<MASTER_SECRET_LEN; i++)
    {
        theMasterSecret[i] = md5Block[i] ^ shaBlock[i];
    }
}


/******************************************************************************
* Function:     CalcKeysFromMaster1
*
* Description:  Calculate keys from master secret using SSL 3.1 (TLS 1.0).
*               This function may be called twice causing redundant calculation.
*               Called upon the change cipher spec messages, once for client
*               and another time for server.
*
* Returns:      None.
******************************************************************************/
void CalcKeysFromMaster1
(
    SSL*    pSSL,
    uint    bIsClient
)
{
    int          i, nMacSize = MAC_SECRET_LEN;
    uchar        md5Block[MD5_SIZE*5];
    uchar        shaBlock[SHA1_SIZE*4];
    const char*  pLabel = "key expansion";
    const int    nLSize = strlen(pLabel);
    const uchar* p1;
    const uchar* p2;
    VDATA       dataBlocks[6] = {
        {NULL,  0},
        {NULL,  0},
        {(const uchar*)pLabel, nLSize},
        {pSSL->serverRandom, SERVER_RANDOM_LEN},
        {pSSL->clientRandom, CLIENT_RANDOM_LEN},
        {NULL,  0}
        };
    HMAC        hMac;

    memset(md5Block, 0, sizeof(md5Block));
    memset(shaBlock, 0, sizeof(shaBlock));
    memcpy(md5Block, pSSL->masterSecret, (MASTER_SECRET_LEN+1)>>1);
    memcpy(shaBlock, &(pSSL->masterSecret[PRE_MASTER_SECRET_LEN>>1]), (PRE_MASTER_SECRET_LEN+1)>>1);

    memset(md5Block, 0, sizeof(md5Block));
    memset(shaBlock, 0, sizeof(shaBlock));

    dataBlocks[1].pData = NULL;
    dataBlocks[1].nSize = 0;

    dataBlocks[0].pData = &(pSSL->masterSecret[0]);
    dataBlocks[0].nSize = ((MASTER_SECRET_LEN+1)>>1);
    HMAC_InitMD5(&hMac, md5Block, &(dataBlocks[0]));

    dataBlocks[0].pData = &(pSSL->masterSecret[MASTER_SECRET_LEN>>1]);
    dataBlocks[0].nSize = ((MASTER_SECRET_LEN+1)>>1);
    HMAC_InitSHA1(&hMac, shaBlock, &(dataBlocks[0]));

    //First calculate P_MD5. See http://www.ietf.org/rfc/rfc2246.txt and rfc4104.txt.

    //Calculate A(1);
    HMAC_MD5 (&hMac, &(md5Block[MD5_SIZE*0]), &(dataBlocks[2]));
    HMAC_SHA1(&hMac, &(shaBlock[SHA1_SIZE*0]), &(dataBlocks[2]));

    //Calculate A(2);
    dataBlocks[0].pData = &(md5Block[MD5_SIZE*0]);
    dataBlocks[0].nSize = MD5_SIZE;
    HMAC_MD5 (&hMac, &(md5Block[MD5_SIZE*1]), &(dataBlocks[0]));
    dataBlocks[0].pData = &(shaBlock[SHA1_SIZE*0]);
    dataBlocks[0].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMac, &(shaBlock[SHA1_SIZE*1]), &(dataBlocks[0]));

    //Calculate A(3);
    dataBlocks[0].pData = &(md5Block[MD5_SIZE*1]);
    dataBlocks[0].nSize = MD5_SIZE;
    HMAC_MD5 (&hMac, &(md5Block[MD5_SIZE*2]), &(dataBlocks[0]));
    dataBlocks[0].pData = &(shaBlock[SHA1_SIZE*1]);
    dataBlocks[0].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMac, &(shaBlock[SHA1_SIZE*2]), &(dataBlocks[0]));

    //Calculate A(4);
    dataBlocks[0].pData = &(md5Block[MD5_SIZE*2]);
    dataBlocks[0].nSize = MD5_SIZE;
    HMAC_MD5 (&hMac, &(md5Block[MD5_SIZE*3]), &(dataBlocks[0]));
    dataBlocks[0].pData = &(shaBlock[SHA1_SIZE*2]);
    dataBlocks[0].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMac, &(shaBlock[SHA1_SIZE*3]), &(dataBlocks[0]));

    //Calculate A(5) for HMAC_MD5 only. To get a minimum 72 bytes keyblock
    if (CIPHER_RSA_RC4_128_SHA  == pSSL->ePendingCipher)
    {
    dataBlocks[0].pData = &(md5Block[MD5_SIZE*3]);
    dataBlocks[0].nSize = MD5_SIZE;
    HMAC_MD5 (&hMac, &(md5Block[MD5_SIZE*4]), &(dataBlocks[0]));
    }

    //Now calculate HMAC_MD5 and HMAC_SHA1.

    //Calculate HMAC_MD5(1) and HMAC_SHA1(1)
    dataBlocks[1].pData = &(md5Block[MD5_SIZE*0]);
    dataBlocks[1].nSize = MD5_SIZE;
    HMAC_MD5 (&hMac, &(md5Block[MD5_SIZE*0]), &(dataBlocks[1]));
    dataBlocks[1].pData = &(shaBlock[SHA1_SIZE*0]);
    dataBlocks[1].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMac, &(shaBlock[SHA1_SIZE*0]), &(dataBlocks[1]));

    //Calculate HMAC_MD5(2) and HMAC_SHA1(2)
    dataBlocks[1].pData = &(md5Block[MD5_SIZE*1]);
    dataBlocks[1].nSize = MD5_SIZE;
    HMAC_MD5 (&hMac, &(md5Block[MD5_SIZE*1]), &(dataBlocks[1]));
    dataBlocks[1].pData = &(shaBlock[SHA1_SIZE*1]);
    dataBlocks[1].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMac, &(shaBlock[SHA1_SIZE*1]), &(dataBlocks[1]));

    //Calculate HMAC_MD5(3) and HMAC_SHA1(3)
    dataBlocks[1].pData = &(md5Block[MD5_SIZE*2]);
    dataBlocks[1].nSize = MD5_SIZE;
    HMAC_MD5 (&hMac, &(md5Block[MD5_SIZE*2]), &(dataBlocks[1]));
    dataBlocks[1].pData = &(shaBlock[SHA1_SIZE*2]);
    dataBlocks[1].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMac, &(shaBlock[SHA1_SIZE*2]), &(dataBlocks[1]));

    //Calculate HMAC_MD5(4) and HMAC_SHA1(4)
    dataBlocks[1].pData = &(md5Block[MD5_SIZE*3]);
    dataBlocks[1].nSize = MD5_SIZE;
    HMAC_MD5 (&hMac, &(md5Block[MD5_SIZE*3]), &(dataBlocks[1]));
    dataBlocks[1].pData = &(shaBlock[SHA1_SIZE*3]);
    dataBlocks[1].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMac, &(shaBlock[SHA1_SIZE*3]), &(dataBlocks[1]));

    //Calculate HMAC_MD5(5) only. To get a minimum 72 bytes keyblock
    if (CIPHER_RSA_RC4_128_SHA  == pSSL->ePendingCipher)
    {
    dataBlocks[1].pData = &(md5Block[MD5_SIZE*4]);
    dataBlocks[1].nSize = MD5_SIZE;
    HMAC_MD5 (&hMac, &(md5Block[MD5_SIZE*4]), &(dataBlocks[1]));
    }

    //Finally calculate the key block from P_MD5 and P_SHA1.
    p1 = md5Block;
    p2 = shaBlock;

    nMacSize = MAC_SECRET_LEN;
    if (CIPHER_RSA_RC4_128_SHA  == pSSL->ePendingCipher)
    {
    nMacSize = SHA1_SIZE;
    }

    if (bIsClient)
    for (i=0; i<nMacSize; i++)
    {
        pSSL->clientMacSecret[i] = (*p1++) ^ (*p2++);
    }
    else
    {
        p1 += nMacSize; p2 += nMacSize;
    }

    if (bIsClient)
    {
        p1 += nMacSize; p2 += nMacSize;
    }
    else
    for (i=0; i<nMacSize; i++)
    {
        pSSL->serverMacSecret[i] = (*p1++) ^ (*p2++);
    }

    //Handle special case of 40 bits key. This is yet to be verified.
    if (CIPHER_RSA_RC4_40_MD5 == pSSL->ePendingCipher)
    {
        union {
            uchar   digest[MD5_SIZE];
            struct  {
                uchar   seedClientKey[5];
                uchar   seedServerKey[5];
                uchar   unUsed[6];
            }       keySeeds;
        }       theSeed;
        MD5 md5;
        const CIPHER* pMd5 = &(gpCipherSet->md5);

        //Output next 16 bytes of key block, first 5 bytes used to seed generation
        //of ClientWriteKey, the next 5 bytes for generation of ServerWriteKey.
        for (i=0; i<MD5_SIZE; i++)
        {
            theSeed.digest[i] = (*p1++) ^ (*p2++);
        }

        if (bIsClient)
        {
        pMd5->Init(&md5, pMd5->pIData);
        pMd5->Input(&md5, theSeed.keySeeds.seedClientKey, sizeof(theSeed.keySeeds.seedClientKey));
        pMd5->Input(&md5, pSSL->clientRandom, sizeof(pSSL->clientRandom));
        pMd5->Input(&md5, pSSL->serverRandom, sizeof(pSSL->serverRandom));

        //Output the ClientWriteKey, i.e., MD5 hash of the seed, clientRandom and ServerRandom.
        pMd5->Digest(&md5, pSSL->clientWriteKey);
        }
        else
        {
        //Now generate the ServerWriteKey.
        pMd5->Init(&md5, pMd5->pIData);
        pMd5->Input(&md5, theSeed.keySeeds.seedServerKey, sizeof(theSeed.keySeeds.seedClientKey));
        pMd5->Input(&md5, pSSL->serverRandom, sizeof(pSSL->serverRandom));
        pMd5->Input(&md5, pSSL->clientRandom, sizeof(pSSL->clientRandom));

        //Output the ClientWriteKey, i.e., MD5 hash of the seed, clientRandom and ServerRandom.
        pMd5->Digest(&md5, pSSL->serverWriteKey);
        }

        //We are done here for the 40 bits key special case.
        return;
    }

    if (bIsClient)
    for (i=0; i<WRITE_KEY_LEN; i++)
    {
        pSSL->clientWriteKey[i] = (*p1++) ^ (*p2++);
    }
    else
    {
        p1 += WRITE_KEY_LEN; p2 += WRITE_KEY_LEN;
    }

    if (bIsClient)
    {
        p1 += WRITE_KEY_LEN; p2 += WRITE_KEY_LEN;
    }
    else
    for (i=0; i<WRITE_KEY_LEN; i++)
    {
        pSSL->serverWriteKey[i] = (*p1++) ^ (*p2++);
    }
}
//---------------------------------------------------------------------------------------------
/******************************************************************************
* Function:     SSL_Initialize
*
* Description:  Initialize SSL module. This call must preceeds any other SSL
*               calls. Application optionally provides memory allocation,
*               memory free, and random number generator functions.
*
* Returns:      SSL_OK if no error.
******************************************************************************/
SSL_RESULT SSL_Initialize
(
    SSL_MALLOC      pMallocFunc,
    SSL_FREE        pFreeFunc,
    SSL_RANDOM      pRandomFunc,
    const CIPHERSET* pCipherSet,
    uint            nSvrMsgSize,
    uint            nAppMsgSize
)
{
    gfMalloc    = pMallocFunc;
    gfFree      = pFreeFunc;
    gfRandom    = pRandomFunc;
    gpCipherSet = pCipherSet;

    StartCerts(pMallocFunc, pFreeFunc, pCipherSet);

    if( nSvrMsgSize > 0 )
    {
        gSvrMsgSize = nSvrMsgSize ;
    }

    if( nAppMsgSize > 0 )
    {
        gAppMsgSize = nAppMsgSize ;
    }

    return SSL_OK;
}


/******************************************************************************
* Function:     SSL_AddRootCertificate
*
* Description:  This function is used to add trusted root certificates.
*               Selected *.cer files dumped from the InternetExplorer
*               root certificates are OK, as long as the associated entities
*               can continue to be trusted.
*
* Returns:      SSL_OK if no error.
******************************************************************************/
SSL_RESULT SSL_AddRootCertificate
(
    const uchar*    pCertData,
    uint            nLen,
    uint            nUnixTime
)
{
    CERT_STATUS     eStatus = CS_ROOT;
    uint    nLen2;
    CERT*           pCert = NULL;

    pCert = CreateCert(eStatus, nUnixTime);

    nLen2 = ParseCert(pCert, pCertData, nLen);

    if (nLen2 != nLen)
    {
        DestroyCert(pCert);
        return SSL_ERROR_CERTIFICATE_BAD;
    }

    eStatus = AuthenticateCert(pCert, NULL);

    if (NULL == InsertCert(pCert, NULL))
    {
        DestroyCert(pCert);
        return SSL_ERROR_CERTIFICATE_EXISTS;
    }

    return SSL_OK;
}

/******************************************************************************
* Function:     SSL_AddCRL
*
* Description:  This function is used to add CRL (Certificate RevocationList).
*               Application should obtain current (up to date) CRLs from the
*               internet. One source is:
*                   http://www.geotrust.com/resources/crls/index.htm
*
* Returns:      SSL_OK if no error.
******************************************************************************/
SSL_RESULT SSL_AddCRL(uchar* pCRL, uint nLen)
{
    // TO be implemented.
    return SSL_RESULT_NOT_APPLY;
}


void SSL_Reset(HSSL pSSL)
{
    if (NULL == pSSL) return;

    pSSL->nSessionIDLen = 0;
    pSSL->serverMsgLen = 0;
    pSSL->serverMsgOff = 0;
    pSSL->nNetOutSize = 0;
    pSSL->nAppOutSize = 0;

    pSSL->pTemp = NULL;
    pSSL->nTemp1 = 0;
    pSSL->nTemp2 = 0;
    pSSL->eLastError = SSL_OK;

    if (pSSL->pServerCert != NULL)
    {
        DeleteCert(pSSL->pServerCert, &(pSSL->pMidCerts));
        DestroyCert(pSSL->pServerCert);
        pSSL->pServerCert = NULL;
    }

    if (pSSL->pMidCerts != NULL)
    {
        CleanupCerts(&(pSSL->pMidCerts));
    }

    pSSL->eState = SSLSTATE_INITIALIZED;
}


/******************************************************************************
* Function:     SSL_Create
*
* Description:  Create an instance of HSSL to be used in a HTTPS connection session.
*
* Returns:      SSL_OK if successful.
******************************************************************************/
SSL_RESULT SSL_Create
(
    HSSL*           pHSSL,
    CERTKEY_INFO*   pCertKey
)
{
    SSL*    pSSL;

    pSSL = gfMalloc(sizeof(*pSSL));
    *pHSSL = NULL;
    if (NULL != pSSL)
    {
        memset(pSSL, 0, sizeof(*pSSL));

        pSSL->pCertKey = pCertKey;

        pSSL->eState = SSLSTATE_INITIALIZED;
        nSSLInstanceCount ++;

        pSSL->serverMsg = gfMalloc( gSvrMsgSize );
        if (gAppMsgSize > 0)
        {
        pSSL->appoutMsg = gfMalloc( gAppMsgSize );
        }

        if ((NULL != pSSL->serverMsg) && ((NULL != pSSL->appoutMsg) || (gAppMsgSize <= 0)))
        {
            pSSL->eLastError = SSL_OK;
            *pHSSL = pSSL;
            SSL_Reset(pSSL);
            return SSL_OK;
        }
        else
        {
            SSL_Destroy(pSSL);
            pSSL = NULL;
        }
    }

    return SSL_ERROR_MEMORY;
}


/******************************************************************************
* Function:     SSL_Destroy
*
* Description:  Destroy an instance of HSSL. The instance should no longer be used.
*
* Returns:      SSL_OK
******************************************************************************/
SSL_RESULT SSL_Destroy(HSSL pSSL)
{
    if (NULL != pSSL)
    {
        if (pSSL->pServerCert)
        {
            CERT*   pCert;

            pCert = DeleteCert(pSSL->pServerCert, &(pSSL->pMidCerts));
            DestroyCert(pSSL->pServerCert);
        }

        if (pSSL->pMidCerts != NULL)
        {
            CleanupCerts(&(pSSL->pMidCerts));
        }

        if ((NULL != pSSL->appoutMsg) && (gAppMsgSize != 0))
        {
            gfFree( pSSL->appoutMsg );
            pSSL->appoutMsg = NULL;
        }
        if (NULL != pSSL->serverMsg)
        {
            gfFree( pSSL->serverMsg );
            pSSL->serverMsg = NULL;
        }

        gfFree(pSSL);

        nSSLInstanceCount--;
        if (nSSLInstanceCount == 0)
        {
            //We no longer have any instance of SSL. What to do?
        }
    }

    return SSL_OK;
}


/******************************************************************************
* Function:     SSL_Process
*
* Description:  The one big callback function that handles everything.
*
* Returns:      
******************************************************************************/
//The filtering function that carries out all SSL operations.
SSL_RESULT SSL_Process
(
    SSL_PARAMS* pParam,
    HSSL        pSSL
)
{
    uint nAppOutBuffSize = gAppMsgSize;

    if ((NULL == pSSL) || (NULL == pParam))
    {
        return SSL_ERROR_GENERIC;
    }

    pSSL->eLastError = SSL_OK;

    //Reset return parameters so we do not unintentionally return something.
    pParam->pNetOutData = NULL;
    pParam->nNetOutSize = 0;

    if (nAppOutBuffSize == 0)
    {
        pSSL->appoutMsg = pParam->pAppOutData;
        nAppOutBuffSize = pParam->nAppOutSize;
    }
    pParam->pAppOutData = NULL;
    pParam->nAppOutSize = 0;

    pSSL->nNetOutSize = 0;
    pSSL->nAppOutSize = 0;

    //First update our time. The time is a UINT32 seconds since
    //the EPOCH, 00:00AM 01/01/1970 UTC.
    pSSL->nCurrentTime = pParam->nUnixTime;

    //Second do we have a state change?
    if (pParam->eState != pSSL->eState)
    {
        pSSL->eState = pParam->eState;
        switch (pSSL->eState)
        {
        case SSLSTATE_RESET:
            SSL_Reset(pSSL);
            pSSL->eState = SSLSTATE_INITIALIZED;
            break;

        case SSLSTATE_TCPCONNECTED:
            {
                pSSL->nStartTime = pSSL->nCurrentTime;
                pSSL->eClientCipher = CIPHER_NOTSET;
                pSSL->eServerCipher = CIPHER_NOTSET;
                pSSL->serverMsgOff = 0;
                pSSL->serverMsgLen = 0;
                pSSL->eState = SSLSTATE_HANDSHAKE_BEGIN;
            }
            break;

        case SSLSTATE_DISCONNECT:
            {
                //We were told by the App to initiate disconnect sequence.
                //This is done by sending a Close Alert to the server, then
                //notify the App to disconnect the TCP.
                CreateAlertMsg(pSSL, ALERT_WARNING, ALERT_NOTIFY_CLOSE);
                pSSL->eState = SSLSTATE_DISCONNECTING;
            }
            break;

        case SSLSTATE_DISCONNECTED:
            {
                //Do some cleanup and prepare for next connection.
                pSSL->eState = SSLSTATE_UNCONNECTED;
            }
            break;

        default:
            break;
        }
    }
    pParam->eState = pSSL->eState;

    //Third do we have anything from the network?
    while ((NULL != pParam->pNetInData) && (pParam->nNetInSize > 0))
    {
        uint    nParse, nChunk = pParam->nNetInSize;

        if (nAppOutBuffSize == 0)
        {
            //Neither Application provided the AppOut buffer, nor was it allocated
            //internally. So we share the serverMsg buffer. Nothing to do here.
        }
        else
        {
            if (nChunk > ((nAppOutBuffSize)>>1))
            {
                nChunk = ((nAppOutBuffSize)>>1);
            }

            //Do we have big enough App Out buffer to parse the message
            if ((nChunk + pSSL->nAppOutSize) > nAppOutBuffSize)
            {
                if ((SSL_OVERHEAD + pSSL->nAppOutSize) < nAppOutBuffSize)
                {
                    nChunk = nAppOutBuffSize - pSSL->nAppOutSize;
                }
                else
                {
                    //Buffer full. Can not parse anything.
                    nChunk = 0;
                    pSSL->eLastError = SSL_ERROR_BUFFER_FULL;
                    return pSSL->eLastError;
                }
            }
        }

        nParse = ParseServerMsg(
            pSSL, 
            pParam->pNetInData,
            nChunk
            );

        pParam->pNetInData += nParse;
        pParam->nNetInSize -= nParse;

        //Any error parsing server message?
        if (pSSL->eLastError != SSL_OK)
        {
            return pSSL->eLastError;
        }
    }

    //Fourth do we have any state change because of server message parsing?
    do
    {
        pParam->eState = pSSL->eState;
        switch (pSSL->eState)
        {
        case SSLSTATE_HANDSHAKE_BEGIN:
            //We create a ClientHello message and ask App to send it.
            pSSL->eState = SSLSTATE_CLIENT_HELLO;
            pSSL->nNetOutSize += CreateClientHelloMsg(
                pSSL,
                &(pSSL->netoutMsg[pSSL->nNetOutSize]),
                (sizeof(pSSL->netoutMsg) - pSSL->nNetOutSize)
                );
            //We now wait for a ServerHello message.
            pSSL->eState = SSLSTATE_SERVER_HELLO;
            break;

        case SSLSTATE_CERTIFICATE_REQUEST:
            pParam->eState = pSSL->eState = SSLSTATE_CERTIFICATE_REQUESTING;
            break;

        case SSLSTATE_CERTIFICATE_REQUESTING:
            pSSL->eState = SSLSTATE_CERTIFICATE_NOTGIVEN;
            break;

        case SSLSTATE_CERTIFICATE_NOTGIVEN:
            pSSL->eState = SSLSTATE_ABORTING;
            break;

        case SSLSTATE_CERTIFICATE_SUPPLIED:
            //OK App gives up the client certificate.
            //Take the client certificate that the application gives us here.
            //Then do appropriate processing here.
            pSSL->pTemp  = (uchar*)pParam->nInXData.ptr; //Only place this is set.
            pSSL->eState = SSLSTATE_CERTIFICATE_VERIFY;
            break;

        case SSLSTATE_CERTIFICATE_VERIFY:
            {
                //Verify server certificate.
                CERT_STATUS eStatus;

                eStatus = AuthenticateCert(pSSL->pServerCert, &(pSSL->pMidCerts));

                //Give the HCERT to let App do something with it.
                pParam->nOutXData.ptr = (void*)pSSL->pServerCert;

                //Please note here. The certificate may or may not be verified,
                //depends on eStatus. That information is passed to application
                //using pParam->nOutXData. So upon seeing the state changing to
                //SSLSTATE_CERTIFICATE_VERIFIED, the application should be able
                //to look at the returned pParam->nOutXData, and decide what to
                //do next if the verify status does not look good. By default it
                //just continues on to SSLSTATE_CLIENT_KEYEXCHANGE, if no action
                //is taken by application.

                if ((eStatus & (CS_OK | CS_VERIFIED)) == (CS_OK | CS_VERIFIED))
                {
                    //Certificate is OK and can be trusted.
                    pParam->eState = pSSL->eState = SSLSTATE_CERTIFICATE_VERIFIED;
                }
                else
                {
                    //Certificate questionable. Prompt the application to decide
                    //either to goto
                    //      SSLSTATE_CERTIFICATE_ACCEPTED
                    //or to goto
                    //      SSLSTATE_CERTIFICATE_REJECTED
                    //Application should check pParam->nOutXData to decide.
                    pParam->eState = pSSL->eState = SSLSTATE_CERTIFICATE_ACCEPTING;
                }
            }
            break;

        case SSLSTATE_CERTIFICATE_VERIFIED:
            //Certificate OK, valid and trusted. So go ahead.
            pSSL->eState = SSLSTATE_CLIENT_KEYEXCHANGE;
            if (pSSL->pTemp != NULL)
            {
                //If we are to supply client certificate, then do it first.
                pSSL->eState = SSLSTATE_CLIENT_CERTIFICATE;
            }
            break;

        case SSLSTATE_CERTIFICATE_ACCEPTED:
            //Certificate may be questionable. But App accepted it any way.
            pSSL->eState = SSLSTATE_CLIENT_KEYEXCHANGE;
            if (pSSL->pTemp != NULL)
            {
                //If we are to supply client certificate, then do it first.
                pSSL->eState = SSLSTATE_CLIENT_CERTIFICATE;
            }
            break;

        case SSLSTATE_CERTIFICATE_ACCEPTING:
            //The application undeciding on this one. So we do the default and
            //prepare to disconnect the questionable connection.
            //Fall through to SSLSTATE_CERTIFICATE_REJECTED as default.
        case SSLSTATE_CERTIFICATE_REJECTED:
            pSSL->eState = SSLSTATE_ABORTING;
            break;

        case SSLSTATE_CLIENT_CERTIFICATE:
            //Same as SSLSTATE_CLIENT_KEYEXCHANGE but with extra messages, depending on pSSL->pTemp,
            //namely the client certificate message and client certificate verify message.
            pSSL->nNetOutSize += CreateClientKeyExchangeMsg(
                pSSL,
                &(pSSL->netoutMsg[pSSL->nNetOutSize]),
                (sizeof(pSSL->netoutMsg) - pSSL->nNetOutSize)
                );
            pSSL->eState = SSLSTATE_CLIENT_FINISH1;
            break;

        case SSLSTATE_CLIENT_KEYEXCHANGE:
            pSSL->nNetOutSize += CreateClientKeyExchangeMsg(
                pSSL,
                &(pSSL->netoutMsg[pSSL->nNetOutSize]),
                (sizeof(pSSL->netoutMsg) - pSSL->nNetOutSize)
                );
            pSSL->eState = SSLSTATE_CLIENT_FINISH1;
            break;

        case SSLSTATE_CLIENT_FINISH1:
            //First send the client ChangeCipherSpec message.
            pSSL->nNetOutSize += CreateChangeCipherSpecMsg(
                pSSL,
                &(pSSL->netoutMsg[pSSL->nNetOutSize]),
                (sizeof(pSSL->netoutMsg) - pSSL->nNetOutSize)
                );
            //Then send the ClientFinished message.
            pSSL->nNetOutSize += CreateClientFinishedMsg(
                pSSL,
                &(pSSL->netoutMsg[pSSL->nNetOutSize]),
                (sizeof(pSSL->netoutMsg) - pSSL->nNetOutSize)
                );
            if (pSSL->eServerCipher == CIPHER_NOTSET)
            {
                pSSL->eState = SSLSTATE_SERVER_FINISH2;
            }
            else
            {
                pSSL->eState = SSLSTATE_HANDSHAKE_DONE;
            }
            break;

        case SSLSTATE_CLIENT_FINISH2:
            //First send the client ChangeCipherSpec message.
            pSSL->nNetOutSize += CreateChangeCipherSpecMsg(
                pSSL,
                &(pSSL->netoutMsg[pSSL->nNetOutSize]),
                (sizeof(pSSL->netoutMsg) - pSSL->nNetOutSize)
                );
            //Then send the ClientFinished message.
            pSSL->nNetOutSize += CreateClientFinishedMsg(
                pSSL,
                &(pSSL->netoutMsg[pSSL->nNetOutSize]),
                (sizeof(pSSL->netoutMsg) - pSSL->nNetOutSize)
                );
            pSSL->eState = SSLSTATE_HANDSHAKE_DONE;
            break;

        case SSLSTATE_HANDSHAKE_DONE:
            pSSL->eState = SSLSTATE_CONNECTED;
            break;

        case SSLSTATE_CONNECTED:
            //We are fully connected. Hope to stay that way indefinitely.
            break;

        case SSLSTATE_ABORT:
            //There is an internal error processing the incoming message, so bail out
            pParam->eState = pSSL->eState = SSLSTATE_ABORTING;
            break;

        case SSLSTATE_ABORTING:
            //TODO: May need to send an abort message to the server here.
            //After the abort message is sent. Set the below state. Application then
            //should disconnect the TCP, and change state to SSLSTATE_DISCONNECTED.
            pSSL->eState = SSLSTATE_ABORTED;
            break;

        default:
            break;
        }
    } while (pParam->eState != pSSL->eState);


    //Fifth do we have any application data that needs to be sent out?
    if ((pParam->nAppInSize > 0) && (NULL != pParam->pAppInData))
    {
        uint    nMsgSize;

        //if (pSSL->eState != SSLSTATE_CONNECTED)
        if (pSSL->eClientCipher == CIPHER_NOTSET)
        {
            return SSL_ERROR_NOTREADY;
        }

        nMsgSize = CreateNetMsg(
            pSSL,
            CONTENT_APPLICATION_DATA,
            pParam->pAppInData,
            pParam->nAppInSize
            );

        if (nMsgSize > 0)
        {
            //The outgoing message is processed successfully
            pParam->nAppInSize = 0;
        }
    }

    //Finally return anything that needs to be returned to the caller.
    if (pSSL->nNetOutSize > 0)
    {
        pParam->pNetOutData = pSSL->netoutMsg;
        pParam->nNetOutSize = pSSL->nNetOutSize;
    }

    if (pSSL->nAppOutSize > 0)
    {
        pParam->pAppOutData = pSSL->appoutMsg;
        pParam->nAppOutSize = pSSL->nAppOutSize;
    }

    if (gAppMsgSize == 0)
    {
        //The buffer was Application provided, so dis-own it.
        pSSL->appoutMsg = NULL;
        pSSL->nAppOutSize = 0;
    }

    return SSL_OK;
}


/******************************************************************************
* Function:     SSL_Cleanup
*
* Description:  The cleanup function that should be the last SSL function to be called.
*
* Returns:      SSL_OK.
******************************************************************************/
SSL_RESULT SSL_Cleanup()
{
    CleanupCerts(NULL);

    gfRandom = NULL;
    gfFree   = NULL;
    gfMalloc = NULL;
    gSvrMsgSize = 0;
    gAppMsgSize = 0;

    return SSL_OK;
}


/******************************************************************************
* Function:     DigestInit
*
* Description:  Initialize the SSL message digests.
*
* Returns:      None
******************************************************************************/
void DigestInit
(
    SSL*    pSSL
)
{
    gpCipherSet->md5.Init(&(pSSL->md5Ctx), gpCipherSet->md5.pIData);
    gpCipherSet->sha1.Init(&(pSSL->sha1Ctx), gpCipherSet->sha1.pIData);
}


/******************************************************************************
* Function:     DigestMsg
*
* Description:  Calculate accumulated SSL message digest
*
* Returns:      None
******************************************************************************/
void DigestMsg
(
    SSL*            pSSL,
    const uchar*    pMsg,
    uint            nMsgLen
)
{
    gpCipherSet->md5.Input(&(pSSL->md5Ctx), pMsg, nMsgLen);
    gpCipherSet->sha1.Input(&(pSSL->sha1Ctx), pMsg, nMsgLen);
}


/******************************************************************************
* Function:     DigestInit1
*
* Description:  Initialize message digest context in pBlock.
*
* Returns:      None.
******************************************************************************/
void DigestInit1
(
    EBLOCK*     pBlock
)
{
    gpCipherSet->md5.Init(&(pBlock->md5Hash), gpCipherSet->md5.pIData);
    gpCipherSet->sha1.Init(&(pBlock->sha1Hash), gpCipherSet->sha1.pIData);
}


/******************************************************************************
* Function:     DigestInit2
*
* Description:  Transfer message digest context to pBlock.
*
* Returns:      None.
******************************************************************************/
void DigestInit2
(
    const SSL*  pSSL,
    EBLOCK*     pBlock
)
{
    pBlock->md5Hash  = pSSL->md5Ctx;
    pBlock->sha1Hash = pSSL->sha1Ctx;
}


/******************************************************************************
* Function:     DigestBlock
*
* Description:  Calculate the digest of previous digest results.
*
* Returns:      None.
******************************************************************************/
void DigestBlock(EBLOCK* pBlock)
{
    gpCipherSet->md5.Input(&(pBlock->md5Hash),  pBlock->md5Digest,  MD5_SIZE);
    gpCipherSet->sha1.Input(&(pBlock->sha1Hash), pBlock->sha1Digest, SHA1_SIZE);
}


/******************************************************************************
* Function:     DigestMsg2
*
* Description:  Calculate message digest on pBlock.
*
* Returns:      None.
******************************************************************************/
void DigestMsg2
(
    EBLOCK*         pBlock,
    const uchar*    pMsg,
    uint            nMsgLen
)
{
    gpCipherSet->md5.Input(&(pBlock->md5Hash), pMsg, nMsgLen);
    gpCipherSet->sha1.Input(&(pBlock->sha1Hash), pMsg, nMsgLen);
}


/******************************************************************************
* Function:     DigestPad2
*
* Description:  Digest pad bytes. Note number of bytes digested is different
*               for MD5 and SHA1
*
* Returns:      None
******************************************************************************/
void DigestPad2
(
    EBLOCK*         pBlock,
    const uchar*    pPad
)
{
    gpCipherSet->md5.Input(&(pBlock->md5Hash), pPad, PADSIZE_MD5);
    gpCipherSet->sha1.Input(&(pBlock->sha1Hash), pPad, PADSIZE_SHA);
}


/******************************************************************************
* Function:     DigestOut2
*
* Description:  Finalize and output the digests in pBlock
*
* Returns:      
******************************************************************************/
void DigestOut2(EBLOCK* pBlock)
{
    gpCipherSet->md5.Digest(&(pBlock->md5Hash), pBlock->md5Digest);
    gpCipherSet->sha1.Digest(&(pBlock->sha1Hash), pBlock->sha1Digest);
}


/******************************************************************************
* Function:     ParseServerMsg
*
* Description:  Parse the server SSL message
*
* Returns:      Number of bytes copied into serverMsg buffer.
******************************************************************************/
uint ParseServerMsg
(
    SSL*                    pSSL,
    const uchar*    pServerMsg,
    uint            nMsgLen
)
{
    uint    nCopied = 0;
    uint    nParsed = 0;
    uchar*  pMsg;
    int             nCopySize = 0;
    uchar   cContentType, verMajor, verMinor;
    uint    nContentSize = 0, nMsgSize;

    pSSL->eLastError = SSL_OK;

    while (((nMsgLen > 0) || (nParsed > 0)) && (pSSL->eLastError == SSL_OK))
    {
        // First re-align any remainder server message to the beginning
        // of buffer pSSL->serverMsg, if there is unaligned message
        // data from previous parsing. But do it only when we are ready
        // to copy more data from input.
        if ((pSSL->serverMsgOff > 0) && (nMsgLen > 0))
        {
            if ((pSSL->nAppOutSize > 0) && (gAppMsgSize == 0))
            {
                //Can not memmove because we share a buffer. So can not reset
                //pSSL->serverMsgOff to 0, even if pSSL->serverMsgLen is 0.
            }
            else
            {
                if (pSSL->serverMsgLen > 0)
                {
                    memmove(
                        pSSL->serverMsg,
                        pSSL->serverMsg+pSSL->serverMsgOff,
                        pSSL->serverMsgLen
                        );
                }
                pSSL->serverMsgOff = 0;
            }
        }

        // Second copy what we can from the input buffer into pSSL->serverMsg buffer.
        nCopySize = gSvrMsgSize - pSSL->serverMsgLen - pSSL->serverMsgOff;
        if (nCopySize > (int)nMsgLen)
        {
            nCopySize = nMsgLen;
        }

        if (nCopySize > 0)
        {
            memcpy(pSSL->serverMsg+pSSL->serverMsgOff+pSSL->serverMsgLen, pServerMsg, nCopySize);
            pSSL->serverMsgLen += nCopySize;
            pServerMsg    += nCopySize;
            nCopied += nCopySize;
            nMsgLen -= nCopySize;
        }
        else if (nParsed == 0)
        {
            // The buffer is totally full or we have nothing more to copy.
            // So do not process any more, unless in the last round we have
            // just parsed portion of the message.
            break;
        }

        // Third parse the message in pSSL->serverMsg. One at a time.
        nParsed = 0;
        pMsg = pSSL->serverMsg + pSSL->serverMsgOff;

        // The CONTENT_HEADER_LEN = 5 bytes goes like this:
        // 1 content type
        // 1 major version
        // 1 minor version
        // 2 content length (MSB LSB)
        if (pSSL->serverMsgLen < CONTENT_HEADER_LEN)
        {
            continue;
        }
        cContentType = *pMsg++;
        verMajor     = *pMsg++;
        verMinor     = *pMsg++;
        nContentSize = *pMsg++;
        nContentSize <<= 8;
        nContentSize += *pMsg++;

        if ((verMajor == SSL_VERSION_MAJOR) && (verMinor <= SSL_VERSION_MINOR))
        {
            // We are OK.
        }
        else
        {
            pSSL->eLastError = SSL_ERROR_PARSE;
            break;
        }

        if (pSSL->serverMsgLen < CONTENT_HEADER_LEN + nContentSize)
        {
            // We do not have the complete message yet.
            continue;
        }

        nMsgSize = nContentSize;    //nMsgSize is nContentSize minus the MAC

        //If the cipher has been turned on already. Then we need to decrypt
        switch (pSSL->eServerCipher)
        {
        case CIPHER_NOTSET:
            //No need to decrypt.
            break;
        case CIPHER_RSA_RC4_40_MD5:
        case CIPHER_RSA_RC4_128_MD5:
        case CIPHER_RSA_RC4_128_SHA:
            RC4Code(&(pSSL->serverCipher), pMsg, nContentSize);
            if (0 == VerifyServerMAC(pSSL, cContentType, pMsg, &nMsgSize))
            {
                //We are OK.
            }
            else
            {
                //Corrupted message. What to do?
                pSSL->eLastError = SSL_ERROR_PARSE;
                assert(0);
            }
            break;
        default:
            //Unsupported cipher.
            pSSL->eLastError = SSL_ERROR_PARSE;
            assert(0);
            break;
        }

        if (pSSL->eLastError == SSL_OK) //Then do the switch
        switch (cContentType)
        {
        case CONTENT_CHANGECIPHERSPEC:
            ParseChangeCipherSpec(pSSL, pMsg, nMsgSize);
            break;
        case CONTENT_ALERT:
            ParseAlertMsg(pSSL, pMsg, nMsgSize);
            break;
        case CONTENT_HANDSHAKE:
            ParseHandshake(pSSL, pMsg, nMsgSize);
            break;
        case CONTENT_APPLICATION_DATA:
            ParseAppData(pSSL, pMsg, nMsgSize);
            break;
        default:
            break;
        }

        nParsed = CONTENT_HEADER_LEN + nContentSize;
        pSSL->serverMsgOff += nParsed;
        pSSL->serverMsgLen -= nParsed;
    }

    // Just for debugging
    if( pSSL->serverMsgLen >= gSvrMsgSize )
    {
        // Buffer not big enough. Need to increase pSSL->serverMsg.
        pSSL->eLastError = SSL_ERROR_PARSE;
        assert(0);
    }

    return nCopied;
}


/******************************************************************************
* Function:     ParseHandshake
*
* Description:  Parse an incoming network message that belongs to CONTENT_HANDSHAKE
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint ParseHandshake
(
    SSL*                    pSSL,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    uchar   cMsgType;
    uint    nMsgLen;
    uint    nParsed = 0;

    if (nMsgSize < 4)
    {
        return SSL_ERROR_PARSE;
    }

    while (nParsed < nMsgSize)
    {
        uint        nParseSize;
        const uchar*    pHashData;

        pHashData = pMsg;
        cMsgType = *pMsg++;
        nMsgLen  = *pMsg++;
        nMsgLen <<= 8;
        nMsgLen += *pMsg++;
        nMsgLen <<= 8;
        nMsgLen += *pMsg++;

        nParsed += 4;

        if ((nParsed + nMsgLen) > nMsgSize)
        {
            return SSL_ERROR_PARSE;
        }

        nParseSize = nMsgLen;
        switch (cMsgType)
        {
        case MSG_HELLO_REQUEST:
            //Server request a hello message again, so re-start the handshake.
            pSSL->eState = SSLSTATE_HANDSHAKE_BEGIN;
            break;

        case MSG_CLIENT_HELLO:
            break;

        case MSG_SERVER_HELLO:
            nParseSize = ParseServerHello(pSSL, pMsg, nMsgLen);
            break;

        case MSG_CERTIFICATE:
            nParseSize = ParseCertificateMsg(pSSL, pMsg, nMsgLen);
            break;

        case MSG_SERVER_KEY_EXCHANGE:
            break;

        case MSG_CERTIFICATE_REQUEST:
            nParseSize = ParseCertificateRequest(pSSL, pMsg, nMsgLen);
            break;

        case MSG_SERVER_HELLO_DONE:
            nParseSize = ParseServerHelloDone(pSSL, pMsg, nMsgLen);
            break;

        case MSG_CERTIFICATE_VERIFY:
            break;

        case MSG_CLIENT_KEY_EXCHANGE:
            break;

        case MSG_FINISHED:
            if (0 == VerifyServerFinished(pSSL, pMsg, nMsgLen))
            {
                //ServerFinishedMessage verified OK.
                if (pSSL->eState == SSLSTATE_SERVER_FINISH1)
                {
                    pSSL->eState = SSLSTATE_CLIENT_FINISH2;
                }
                else if (pSSL->eState == SSLSTATE_SERVER_FINISH2)
                {
                    pSSL->eState = SSLSTATE_HANDSHAKE_DONE;
                }
                else
                {
                    //We are in the wrong state to have received
                    //the ServerFinished message. What to do?
                    assert(0);
                }
            }
            else
            {
                //The serverFinished message mismatch. What to do?
                assert(0);
            }
            break;
        }

        pMsg     += nParseSize;
        nParsed  += nParseSize;

        if (cMsgType == MSG_HELLO_REQUEST)
        {
            //http://www.ietf.org/rfc/rfc2246.txt
            if ((pSSL->preMasterSecret[1] < SSL_VERSION_MINOR1) ||
                (SSL_VERSION_MINOR < SSL_VERSION_MINOR1) )
            {
                //Note in RFC2246 it suggest that hello request message is not included in the handshake hask.
                //So probably I should just do a continue here. But not verified yet
                //so I comment out the continue here.
                //See http://www.ietf.org/rfc/rfc2246.txt

                //continue;
            }
        }

        //Hash the handshake content. Hash every handshake message. NOTE
        //for the purpose of calculating FinishedMessage, the HandshakeHash
        //does not include the FinishedMessage itself. So we have to do
        //the HandshakeHash right after we parse the handshake message.
        DigestMsg(pSSL, pHashData, (uint)(pMsg-pHashData));
    }

    return nParsed;
}


/******************************************************************************
* Function:     ParseChangeCipherSpec
*
* Description:  Parse the Change Cipher Spec message. After this point all
*               messages are encrypted.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint ParseChangeCipherSpec
(
    SSL*                    pSSL,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    if ((pSSL->preMasterSecret[1] < SSL_VERSION_MINOR1) ||
        (SSL_VERSION_MINOR < SSL_VERSION_MINOR1) )
    {
        CalcKeysFromMaster(pSSL, ISSERVER);
    }
    else
    {
        CalcKeysFromMaster1(pSSL, ISSERVER);
    }

    //From now on any thing from the server is encrypted.
    pSSL->eServerCipher = pSSL->ePendingCipher;

    //Initialize the server write cipher.
    if ((CIPHER_RSA_RC4_40_MD5  == pSSL->eServerCipher) ||
        (CIPHER_RSA_RC4_128_MD5 == pSSL->eServerCipher) ||
        (CIPHER_RSA_RC4_128_SHA == pSSL->eServerCipher) )
    {
        RC4Init(
            &(pSSL->serverCipher),
            pSSL->serverWriteKey,
            sizeof(pSSL->serverWriteKey)
            );
    }
    else
    {
        //Unsupported cipher.
    }

    //Reset the server write sequence number.
    pSSL->serverSequenceL = 0;
    pSSL->serverSequenceH = 0;

    return nMsgSize;
}


/******************************************************************************
* Function:     ParseServerHello
*
* Description:  Parse the server hello message.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint ParseServerHello
(
    SSL*                    pSSL,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    uint    nParsed = 0;
    uint    nSessionIDLen;
    uint    nPendingCipher;
    uint    nCompression;
    uchar   verMajor, verMinor;

    verMajor = *pMsg++;
    verMinor = *pMsg++;
    nParsed  += 2;

    pSSL->preMasterSecret[0] = SSL_VERSION_MAJOR;
    pSSL->preMasterSecret[1] = (verMinor<SSL_VERSION_MINOR)?verMinor:SSL_VERSION_MINOR;

    // First in server hello msg, two bytes of server version.
    // Do we require the server to be version 3.0, no more, no less?

    // Next 32 bytes (SERVER_RANDOM_SIZE) of ServerRandom.
    memcpy(pSSL->serverRandom, pMsg, SERVER_RANDOM_SIZE);
    pMsg += SERVER_RANDOM_SIZE;
    nParsed  += SERVER_RANDOM_SIZE;

    // Next byte tells session ID length
    nSessionIDLen = (uint)(*pMsg++);
    nParsed  ++;

    if (nSessionIDLen > 0)
    {
        if ((pSSL->nSessionIDLen == nSessionIDLen) &&
            (0 == memcmp(pSSL->sessionID, pMsg, nSessionIDLen)) )
        {
            //No need to do ClientKeyExchange. We re-use the old
            //Pre-Master Secret from the last connection session.
            pSSL->eState = SSLSTATE_SERVER_FINISH1;
        }
        else
        {
            memcpy(pSSL->sessionID, pMsg, nSessionIDLen);
        }
        pMsg += nSessionIDLen;
        nParsed  += nSessionIDLen;
    }
    pSSL->nSessionIDLen = nSessionIDLen;

    // Next two bytes is the pending ciphers.
    nPendingCipher = *pMsg++;
    nPendingCipher <<= 8;
    nPendingCipher += *pMsg++;

    //The final byte is Compression. We support only 0, no compression.
    nCompression = *pMsg++;

    pSSL->ePendingCipher = nPendingCipher;

    nParsed  += 3;

    if (nParsed < nMsgSize)
    {
        //There are extentions to the message
        uint nExtSize0 = 0;
        
        nExtSize0  = *pMsg++;
        nExtSize0 <<= 8;
        nExtSize0 += *pMsg++;
        nParsed   += 2;

        //Parse the message extention here.
        if (nParsed + nExtSize0 <= nMsgSize)
        {
            uint    nExtType = 0;
            uint    nExtSize = 0;
            uint    bAbort = FALSE;

            nExtType  = *pMsg++;
            nExtType <<= 8;
            nExtType += *pMsg++;

            if (nExtType == ((MSG_EXTENTION<<8) | MSG_EXTENTION_RENEGOTIATION))
            {
                nExtSize  = *pMsg++;
                nExtSize <<= 8;
                nExtSize += *pMsg++;

                nExtSize --;

                if (nExtSize != *pMsg++)
                {
                    //Malformed extention message.
                    bAbort = TRUE;
                }
                else if (nExtSize > 0)
                {
                    if (pSSL->eServerCipher == CIPHER_NOTSET)
                    {
                        //Not expecting a non-empty re-negotiation info message.
                        bAbort = TRUE;
                    }
                    else if (memcmp(pSSL->clientVerify, pMsg, (nExtSize>>1)))
                    {
                        bAbort = TRUE;
                    }
                    else if (memcmp(pSSL->serverVerify, pMsg+(nExtSize>>1), (nExtSize>>1)))
                    {
                        bAbort = TRUE;
                    }
                    else
                    {
                        //The expected renegotiation info message matches. So OK here.
                        bAbort = FALSE;
                    }
                    pMsg += nExtSize;
                }
                else if (pSSL->eServerCipher != CIPHER_NOTSET)
                {
                    //We do expect a non-empty re-negotiation info message.
                    bAbort = TRUE;
                }
                else
                {
                    //We expect an empty renegotiation info message. So OK here.
                    bAbort = FALSE;
                }
            }

            if (bAbort)
            {
                //Something wrong with the re-negotiation info message. Bailout.
                pSSL->eState = SSLSTATE_ABORT;
            }
        }
        else
        {
            //Something not quite right here. So just bail out.
            pSSL->eState = SSLSTATE_ABORT;
        }

        nParsed += nExtSize0;
    }

    //assert(nParsed == nMsgSize); // We should have parsed exactly all the bytes.

    return nMsgSize;
}


/******************************************************************************
* Function:     ParseServerHelloDone
*
* Description:  Parse the server hellow done message.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint ParseServerHelloDone
(
    SSL*                    pSSL,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    // Not much to be parsed. Just carry out operations that is needed upon
    // the ServerHelloDone.

    //Make sure we are expecting a ServerHelloDone at this point.

    //Upon receiving a ServerHelloDone, we should verify Server Certificate,
    //Generate the client key exchange message and send out.
    pSSL->pTemp = NULL; //We set it that we have no client certificate.
    if (pSSL->eState == SSLSTATE_SERVER_CERTREQUEST)
    {
        pSSL->eState = SSLSTATE_CERTIFICATE_REQUEST;
    }
    else
    {
        pSSL->eState = SSLSTATE_CERTIFICATE_VERIFY;
    }

    return nMsgSize;
}


/******************************************************************************
* Function:     VerifyServerFinished
*
* Description:  Verify that the server finished message is correctly calculated
*               thus the key exchange handshake is successful.
*
* Returns:      ZERO if no error, else there is an error.
******************************************************************************/
uint VerifyServerFinished
(
    SSL*                    pSSL,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    uchar   serverFinishedMsg[MD5_SIZE+SHA1_SIZE];
    uint   nMsgLen;

    nMsgLen = CreateFinishedMsg(
        pSSL,
        ISSERVER,   //We are constructing a server message
        serverFinishedMsg,
        sizeof(serverFinishedMsg)
        );

    return memcmp(pMsg, serverFinishedMsg, (nMsgLen|nMsgSize));
}


/******************************************************************************
* Function:     ParseCertificateMsg
*
* Description:  Parse the certificate message and extract certificate(s).
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint ParseCertificateMsg
(
    SSL*                    pSSL,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    uint    nParsed = 0;
    uint    nTotalSize;
    uint    nCurrentSize;
    struct CERT*    pCert = NULL;

    // We are parsing a possible list of N certificates.

    // First 3 bytes tells us the the total size we should be parsing.
    //Not including the 3 bytes itself.
    nTotalSize  = *pMsg++;
    nTotalSize<<= 8;
    nTotalSize += *pMsg++;
    nTotalSize<<= 8;
    nTotalSize += *pMsg++;
    nParsed += 3;

    while (nParsed < nMsgSize)
    {
        uint    nCertParsed;

        //Next 3 bytes tells us the size of next certificate to be parsed.
        nCurrentSize  = *pMsg++;
        nCurrentSize<<= 8;
        nCurrentSize += *pMsg++;
        nCurrentSize<<= 8;
        nCurrentSize += *pMsg++;
        nParsed += 3;

        pCert = CreateCert(CS_UNKNOWN, pSSL->nCurrentTime);

        nCertParsed = ParseCert(pCert, pMsg, nCurrentSize);

        pMsg    += nCurrentSize;
        nParsed += nCurrentSize;

        //The very first certificate is the server certificate. Anything that follows
        //are CA certificates that need to be inserted.
        if (pSSL->pServerCert == NULL)
        {
            pSSL->pServerCert = pCert;
        }
        else if (NULL == InsertCert(pCert, &(pSSL->pMidCerts)))
        {
            //Can not insert certificate since it exists already as root.
            //So ignore the one coming from the network.
            DestroyCert(pCert);
        }
    }

    //We received server certificate so next to come is ServerHelloDone.
    pSSL->eState = SSLSTATE_SERVER_HELLO_DONE;

    return nParsed;
}


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

extern struct X509NAME gTempCA;

#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus


/******************************************************************************
* Function:     ParseCertificateRequest
*
* Description:  Parse the certificate request message from the server. This message
*               contains information on CAs whose certificates can be accepted.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint ParseCertificateRequest
(
    SSL*                    pSSL,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    uint    i, nParse, nParsed = 0;
    uint    nTotalSize;
    uint    eCipherType;
    uint    nCipherTypes = 0;

    nCipherTypes  = *pMsg++;    //Number of cipher types. Normally just two.
    nParsed ++;

    //Then a list of nCipherTypes entry of cipher types, one byte each.
    for (i=0; i<nCipherTypes; i++)
    {
        //The server tells us what cipher types it accepts. For now we just ignore it
        //The list is normally just 01 02.
        eCipherType = *pMsg++;
        nParsed ++;
    }

    //Then two bytes for total size of the CA list, in bytes.
    nTotalSize  = *pMsg++;
    nTotalSize<<= 8;
    nTotalSize += *pMsg++;
    nParsed += 2;

    while (nParsed < nMsgSize)
    {
        uint    nCASize = 0;

        //First the size of the CA Identity
        nCASize  = *pMsg++; 
        nCASize <<= 8;
        nCASize += *pMsg++;
        nParsed += 2;

        //Parse each CA Identity. We are supposed to save this information X509NAME caName
        //for later use to find the correct client certificate to use. For now ignore it.
        nParse = ParseX509ID(&gTempCA, pMsg, nCASize);
        //assert(nParse == nCASize);

        pMsg += nParse;
        nParsed += nParse;
    }

    //assert(nParsed == nMsgSize); //Make sure we parsed the exact size.

    //We received server certificate so next to come is ServerHelloDone.
    //We also need to set a flag to indicate we need to get the client certificate.
    pSSL->eState = SSLSTATE_SERVER_CERTREQUEST; //Equivalent to SSLSTATE_SERVER_HELLO_DONE

    return nParsed;
}


/******************************************************************************
* Function:     ParseAppData
*
* Description:  Parse incoming network message that is CONTENT_APPLICATION_DATA.
*               since the data is not SSL handshake but application data to be
*               interpretted by application level code, we simply copy it over.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint ParseAppData
(
    SSL*                    pSSL,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    if (pSSL->appoutMsg == NULL)
    {
        //No buffer. So we share the serverMsg buffer
        pSSL->appoutMsg = (uchar*)pMsg;
    }
    else
    {
    memmove(
        &(pSSL->appoutMsg[pSSL->nAppOutSize]),
        pMsg,
        nMsgSize
        );
    }

    pSSL->nAppOutSize += nMsgSize;

    return nMsgSize;
}


/******************************************************************************
* Function:     CreateFinishedMsg
*
* Description:  Create the Client Finished or Server Finished message. It can
*               be used by both the client and server, depending on the flag.
*
* Returns:      Number of bytes of constructed message.
******************************************************************************/
uint CreateFinishedMsg
(
    SSL*            pSSL,
    uint    bIsClient,  //ISCLIENT=TRUE for Client, ISSERVER=FALSE for Server
    uchar*  pMsgBuff,
    uint    nBuffSize
)
{
    int             i;
    uchar*  pMsg = pMsgBuff;
    MD5             md5Ctx;
    SHA             shaCtx;
    const CIPHER*   pMd5 = &(gpCipherSet->md5);
    const CIPHER*   pSha = &(gpCipherSet->sha1);

    md5Ctx = pSSL->md5Ctx;
    shaCtx = pSSL->sha1Ctx;

    if ((pSSL->preMasterSecret[1] < SSL_VERSION_MINOR1) ||
        (SSL_VERSION_MINOR < SSL_VERSION_MINOR1) )
    {
    //For SSL 3.0
    pMd5->Input(&md5Ctx, bIsClient?SENDER_CLIENT:SENDER_SERVER, 4);
    pMd5->Input(&md5Ctx, pSSL->masterSecret, sizeof(pSSL->masterSecret));
    pMd5->Input(&md5Ctx, PAD1, PADSIZE_MD5);
    pMd5->Digest(&md5Ctx, pMsg);

    //Md5Init(&md5Ctx);
    pMd5->Init(&md5Ctx, pMd5->pIData);

    pMd5->Input(&md5Ctx, pSSL->masterSecret, sizeof(pSSL->masterSecret));
    pMd5->Input(&md5Ctx, PAD2, PADSIZE_MD5);
    pMd5->Input(&md5Ctx, pMsg, MD5_SIZE);
    pMd5->Digest(&md5Ctx, pMsg);
    //Done with MD5 hash calculation

    pMsg += MD5_SIZE;

    //Now we calculate the SHA1 Hash for the Finished Message.
    pSha->Input(&shaCtx, bIsClient?SENDER_CLIENT:SENDER_SERVER, 4);
    pSha->Input(&shaCtx, pSSL->masterSecret, sizeof(pSSL->masterSecret));
    pSha->Input(&shaCtx, PAD1, PADSIZE_SHA);
    pSha->Digest(&shaCtx, pMsg);

    pSha->Input(&shaCtx, pSSL->masterSecret, sizeof(pSSL->masterSecret));
    pSha->Input(&shaCtx, PAD2, PADSIZE_SHA);
    pSha->Input(&shaCtx, pMsg, SHA1_SIZE);
    pSha->Digest(&shaCtx, pMsg);
    //Done with SHA1 hash calculation

    pMsg += SHA1_SIZE;

    }
    else
    {
    //For SSL 3.1
#define pMD5HASH   (&(dataBlock[0]))
#define pSHAHASH   (&(dataBlock[MD5_SIZE]))
#define pMD5DIGEST (&(dataBlock[MD5_SIZE+SHA1_SIZE]))
#define pSHADIGEST (&(dataBlock[MD5_SIZE*2+SHA1_SIZE]))

    const char*     pClientLabel = CLIENT_LABEL;    //"client finished";
    const char*     pServerLabel = SERVER_LABEL;    //"server finished";
    uchar   dataBlock[MD5_SIZE*2+SHA1_SIZE*2];    //A worker data
    VDATA           vectBlocks[5] = {
        {(const uchar*)pClientLabel, 15},
        {NULL, 0},
        {(const uchar*)pClientLabel, 15},
        {pMD5DIGEST, MD5_SIZE+SHA1_SIZE},
        {NULL, 0}
        };
    HMAC            hMAC;

    vectBlocks[0].pData = &(pSSL->masterSecret[0]);
    vectBlocks[0].nSize = ((MASTER_SECRET_LEN+1)>>1);
    HMAC_InitMD5(&hMAC, dataBlock, &(vectBlocks[0]));

    vectBlocks[0].pData = &(pSSL->masterSecret[MASTER_SECRET_LEN>>1]);
    vectBlocks[0].nSize = ((MASTER_SECRET_LEN+1)>>1);
    HMAC_InitSHA1(&hMAC, dataBlock, &(vectBlocks[0]));

    vectBlocks[0].pData = (const uchar*)((bIsClient)?pClientLabel:pServerLabel);
    vectBlocks[0].nSize = 15; //strlen(vectBlocks[0].pData);

    vectBlocks[2] = vectBlocks[0];

    pMd5->Digest(&md5Ctx, pMD5DIGEST);
    pSha->Digest(&shaCtx, pSHADIGEST);

    //Calculate A(1) for HMAC_MD5 and HMAC_SHA1
    HMAC_MD5 (&hMAC, pMD5HASH, &(vectBlocks[2]));
    HMAC_SHA1(&hMAC, pSHAHASH, &(vectBlocks[2]));

    //Calculate HMAC_MD5(1) and HMAC_SHA1(1)
    vectBlocks[1].pData = pMD5HASH;
    vectBlocks[1].nSize = MD5_SIZE;
    HMAC_MD5 (&hMAC, pMD5HASH, &(vectBlocks[1]));
    vectBlocks[1].pData = pSHAHASH;
    vectBlocks[1].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMAC, pSHAHASH, &(vectBlocks[1]));


    for (i=0; i<TLS_VERIFY_LEN; i++)
    {
        *pMsg++ = pMD5HASH[i] ^ pSHAHASH[i];
    }

#undef  pSHADIGEST //(&(dataBlock[MD5_SIZE*2+SHA1_SIZE]))
#undef  pMD5DIGEST //(&(dataBlock[MD5_SIZE+SHA1_SIZE]))
#undef  pSHAHASH   //(&(dataBlock[MD5_SIZE]))
#undef  pMD5HASH   //(&(dataBlock[0]))
    }

    memcpy((bIsClient)?pSSL->clientVerify:pSSL->serverVerify, pMsgBuff, (pMsg-pMsgBuff));

    return (pMsg - pMsgBuff);
}


/******************************************************************************
* Function:     CalculateMAC
*
* Description:  Calculate the MAC signature based on the state of the SSL engine.
*
* Returns:      Size of MAC signature in bytes.
******************************************************************************/
uint CalculateMAC
(
    SSL*            pSSL,
    uint    bIsClient,  //TRUE for Client, FALSE for Server
    uchar*  pMac,
    uchar   cMsgType,
    const uchar*    pMsg,
    uint    nMsgSize
)
{
    SSL_CIPHER      eCipher;
    uint    nMacSize = MD5_SIZE;
    uchar*  pMacSecret;
    uint    nSequenceL, nSequenceH;
    uchar*  pTemp;
    uchar   temp[16];

    //Get the sequence number, and BTW increment it in pSSL.
    if (bIsClient)
    {
        eCipher    = pSSL->eClientCipher;
        pMacSecret = pSSL->clientMacSecret;
        nSequenceL = pSSL->clientSequenceL;
        nSequenceH = pSSL->clientSequenceH;
        if ((++(pSSL->clientSequenceL)) == 0)
        {
            pSSL->clientSequenceH ++;
        }
    }
    else
    {
        eCipher    = pSSL->eServerCipher;
        pMacSecret = pSSL->serverMacSecret;
        nSequenceL = pSSL->serverSequenceL;
        nSequenceH = pSSL->serverSequenceH;
        if ((++(pSSL->serverSequenceL)) == 0)
        {
            pSSL->serverSequenceH ++;
        }
    }

    pTemp = temp;

    *pTemp++ = (uchar)(nSequenceH>>24);
    *pTemp++ = (uchar)(nSequenceH>>16);
    *pTemp++ = (uchar)(nSequenceH>>8);
    *pTemp++ = (uchar)(nSequenceH>>0);

    *pTemp++ = (uchar)(nSequenceL>>24);
    *pTemp++ = (uchar)(nSequenceL>>16);
    *pTemp++ = (uchar)(nSequenceL>>8);
    *pTemp++ = (uchar)(nSequenceL>>0);

    *pTemp++ = cMsgType;

    if ((pSSL->preMasterSecret[1] < SSL_VERSION_MINOR1) ||
        (SSL_VERSION_MINOR < SSL_VERSION_MINOR1) )
    {
    //SSL 3.0 has no version info here.
    }
    else
    {
    //SSL 3.1 has the version bytes here
    *pTemp++ = pSSL->preMasterSecret[0]; //SSL_VERSION_MAJOR;
    *pTemp++ = pSSL->preMasterSecret[1]; //SSL_VERSION_MINOR1;
    }

    *pTemp++ = (uchar)(nMsgSize>>8);
    *pTemp++ = (uchar)(nMsgSize>>0);

    if ((pSSL->preMasterSecret[1] < SSL_VERSION_MINOR1) ||
        (SSL_VERSION_MINOR < SSL_VERSION_MINOR1) )
    //For SSL 3.0
    switch (eCipher)
    {
    case CIPHER_RSA_RC4_40_MD5:
    case CIPHER_RSA_RC4_128_MD5:
        {
            MD5     md5Ctx;
            const CIPHER* pMd5 = &(gpCipherSet->md5);

            nMacSize = MD5_SIZE;

            //Md5Init(&md5Ctx);
            pMd5->Init(&md5Ctx, pMd5->pIData);
            pMd5->Input(&md5Ctx, pMacSecret, MAC_SECRET_LEN);
            pMd5->Input(&md5Ctx, PAD1, PADSIZE_MD5);

            pMd5->Input(&md5Ctx, temp, (uint)(pTemp-temp));
            pMd5->Input(&md5Ctx, pMsg, nMsgSize);

            pMd5->Digest(&md5Ctx, pMac);

            //Md5Init(&md5Ctx);
            pMd5->Init(&md5Ctx, pMd5->pIData);
            pMd5->Input(&md5Ctx, pMacSecret, MAC_SECRET_LEN);
            pMd5->Input(&md5Ctx, PAD2, PADSIZE_MD5);
            pMd5->Input(&md5Ctx, pMac, nMacSize);
            pMd5->Digest(&md5Ctx, pMac);
        }
        break;
    case CIPHER_RSA_RC4_128_SHA:
        {
            SHA     shaCtx;
            const CIPHER*   pSha = &(gpCipherSet->sha1);

            nMacSize = SHA1_SIZE;

            pSha->Init(&shaCtx, pSha->pIData);
            pSha->Input(&shaCtx, pMacSecret, SHA1_SIZE);
            pSha->Input(&shaCtx, PAD1, PADSIZE_SHA);

            pSha->Input(&shaCtx, temp, (uint)(pTemp-temp));
            pSha->Input(&shaCtx, pMsg, nMsgSize);

            pSha->Digest(&shaCtx, pMac);

            pSha->Init(&shaCtx, pSha->pIData);
            pSha->Input(&shaCtx, pMacSecret, SHA1_SIZE);
            pSha->Input(&shaCtx, PAD2, PADSIZE_SHA);
            pSha->Input(&shaCtx, pMac, nMacSize);
            pSha->Digest(&shaCtx, pMac);
        }
        break;
    default:
        //Unsupported cipher. Let's assume MAC size same as MD5.
        assert(0);
        nMacSize = 0;
        break;
    }
    else
    {
    //For SSL 3.1
    uchar   hashBlock[BLOCK_LEN];
    VDATA   vectBlocks[4] = {
        {pMacSecret, MAC_SECRET_LEN},
        {temp, (uint)(pTemp-temp)},
        {pMsg, nMsgSize},
        {NULL, 0}
        };
    HMAC    hMac;

    switch (eCipher)
    {
    case CIPHER_RSA_RC4_40_MD5:
    case CIPHER_RSA_RC4_128_MD5:
        {
            nMacSize = MD5_SIZE;

            HMAC_InitMD5(&hMac, hashBlock, &(vectBlocks[0]));
            HMAC_MD5(&hMac, pMac, &(vectBlocks[1]));
        }
        break;
    case CIPHER_RSA_RC4_128_SHA:
        {
            nMacSize = SHA1_SIZE;
            vectBlocks[0].nSize = SHA1_SIZE;

            HMAC_InitSHA1(&hMac, hashBlock, &(vectBlocks[0]));
            HMAC_SHA1(&hMac, pMac, &(vectBlocks[1]));
        }
        break;
    default:
        //Unsupported cipher. Let's assume MAC size same as MD5.
        nMacSize = 0;
        break;
    }
    }

    return nMacSize;
}


/******************************************************************************
* Function:     EncryptWithMAC
*
* Description:  Calculate the MAC, attach to message and then encrypt.
*
* Returns:      Bytes of the MAC block attached before encryption.
******************************************************************************/
uint EncryptWithMAC
(
    SSL*    pSSL,
    uint    bIsClient,
    uchar   cContentType,
    uchar*  pMsg,
    uint    nMsgSize
)
{
    uint    nMacSize = MD5_SIZE;

    nMacSize = CalculateMAC(
        pSSL,
        bIsClient,
        &(pMsg[nMsgSize]),
        cContentType,
        pMsg,
        nMsgSize
        );

    //Now we do the encryption, after the MAC is appended.
    RC4Code(
        (bIsClient)?(&(pSSL->clientCipher)):(&(pSSL->serverCipher)),
        pMsg,
        nMsgSize+nMacSize
        );

    return nMacSize;
}


/******************************************************************************
* Function:     CreateNetMsg
*
* Description:  Package and encrypt an out-going network data package.
*
* Returns:      Total size of the package when properly encrypted and packaged.
*               ZERO if not enough space to put the package in.
******************************************************************************/
uint CreateNetMsg
(
    SSL*        pSSL,
    uchar       cContentType,
    const uchar* pData,
    uint        nDataSize
)
{
    uint       nLen, nMacSize=MD5_SIZE, nEncryptSize;
    uchar*      pMsgBuff = &(pSSL->netoutMsg[pSSL->nNetOutSize]);
    uchar*      pMsg = pMsgBuff;
    uchar*      pEncryptData;

    //Do we have enough space to contain the package?
    nLen = 5 + nMacSize + nDataSize;
    if ((nLen + pSSL->nNetOutSize) > sizeof(pSSL->netoutMsg))
    {
        return 0; //Not enough space. No package is added, so return 0.
    }

    *pMsg++ = cContentType;

    *pMsg++ = pSSL->preMasterSecret[0]; //SSL_VERSION_MAJOR;
    *pMsg++ = (SSL_VERSION_MINOR<pSSL->preMasterSecret[1])?SSL_VERSION_MINOR:pSSL->preMasterSecret[1];

    nEncryptSize = nDataSize + nMacSize;

    //This content size may not be correct. Will come back to fill in again.
    *pMsg++ = (uchar)(nEncryptSize>>8);
    *pMsg++ = (uchar)(nEncryptSize>>0);

    //Starting here is data that needs to be encrypted.
    pEncryptData = pMsg;

    memcpy(pMsg, pData, nDataSize);
    pMsg += nDataSize;

    //Now calculate the MAC of the message and encrypt.
    pMsg += nMacSize = EncryptWithMAC(
        pSSL, 
        TRUE,       //For Client
        (*pMsgBuff),
        pEncryptData,
        nDataSize
        );

    nEncryptSize = nDataSize + nMacSize;   //Now we added the size of MAC

    pEncryptData[-2] = (uchar)(nEncryptSize>>8);
    pEncryptData[-1] = (uchar)(nEncryptSize>>0);

    nLen = pMsg - pMsgBuff;

    pSSL->nNetOutSize += nLen;

    return nLen;
}


/******************************************************************************
* Function:     ParseAlertMsg
*
* Description:  Parse incoming message that belongs to CONTENT_ALERT.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint ParseAlertMsg
(
    SSL*        pSSL,
    const uchar* pMsg,
    uint        nMsgSize
)
{
    uchar   cCategory, cType;

    cCategory = *pMsg++;
    cType     = *pMsg++;

    switch (cType)
    {
    case ALERT_NOTIFY_CLOSE:
        CreateAlertMsg(pSSL, ALERT_WARNING, ALERT_NOTIFY_CLOSE);
        pSSL->eState = SSLSTATE_DISCONNECTING;
        break;
    default:
        pSSL->eState = SSLSTATE_DISCONNECTING;
        break;
    }

    return nMsgSize;
}


/******************************************************************************
* Function:     CreateAlertMsg
*
* Description:  Create a CONTENT_ALERT message.
*
* Returns:      Bytes of constructed message.
******************************************************************************/
uint CreateAlertMsg
(
    SSL*    pSSL,
    uchar   cCategory,
    uchar   cType
)
{
    uchar       msg[2];

    msg[0] = cCategory;
    msg[1] = cType;

    return CreateNetMsg(pSSL, CONTENT_ALERT, msg, sizeof(msg));
}
//---------------------------------------------------------------------------------------------


};
//---------------------------------------------------------------------------------------------


//---------------------------------------------------------------------------------------------