#ifndef CERT_GEN_INCLUDED_
#define CERT_GEN_INCLUDED_

#include "cert.h"
#include "../../include/cert/x509.h"
#include "../../include/ssl/cipher.h"
#include "../../include/ecc/ecc_p256.h"
#include "../../include/ssl/ssl_defs.h"

struct CIPHERSET;
namespace X509
{
struct X509NAME;
}

struct KEYPAIR
{
 const uint8_t* pPubKey;
 const uint8_t* pPriKey;
 uint32_t       nEccGroup;
};

using ASN::Asn;
using ASN::Asn0;
using ASN::Int;
using ASN::Seq0;
using ASN::Seq1;
using ASN::Seq2;

using X509::CB_DATA;
using X509::X509v3;


class MyCertSet
{
 public:
 const CIPHERSET& cset_;

 const KEYPAIR&        caKeyPair_;
 const KEYPAIR&        subPubKey_;
 const X509::X509NAME& issuer_;
 const X509::X509NAME& subject_;
 const char**          altNames_;
 uint32_t              issueTime_;
 uint32_t              expireTime_;
 uint64_t              serial_;
 uint32_t              n_;

 MyCertSet(const CIPHERSET& c, const KEYPAIR& caKeyPair, const KEYPAIR& subPubKey, const X509::X509NAME& ca, const X509::X509NAME& sub, const char* names[], uint32_t isTime, uint32_t exTime, uint64_t sn) : cset_(c), caKeyPair_(caKeyPair), subPubKey_(subPubKey), issuer_(ca), subject_(sub), altNames_(names), issueTime_(isTime), expireTime_(exTime), serial_(sn), n_(0) { }
};


#ifdef __cplusplus
extern "C"
{
#endif //__cplusplus

static uint myCallback(void* context, const CB_DATA& cbData)
{
 MyCertSet& myCertSet(*static_cast<MyCertSet*>(context));
 switch (cbData.eType)
 {
  case X509::CB_ALGORITHM:
   return (myCertSet.caKeyPair_.nEccGroup) ? OID_HASH_SHA256_ECDSA : OID_HASH_SHA256_RSA;
  case X509::CB_SERIAL:
   *((uint64_t*)cbData.pOut) = myCertSet.serial_;
   return 0;
  case X509::CB_HASH:
   {
    const CIPHERSET& c(((MyCertSet*)context)->cset_);
    const CIPHER&    s(c.sha256);
    s.Hash((const uchar*)cbData.pIn, cbData.nInSize, (uchar*)cbData.pOut);
   }
   break;

  case X509::CB_SUBJECT_NAME:
   {
    X509::X509NAME& name(*reinterpret_cast<X509::X509NAME*>(cbData.pOut));
    name = myCertSet.subject_;
    return 0;
   }

  case X509::CB_ISSUER_NAME:
   {
    X509::X509NAME& name(*reinterpret_cast<X509::X509NAME*>(cbData.pOut));
    name = myCertSet.issuer_;
    return 0;
   }

  case X509::CB_ISSUE_TIME:
   return myCertSet.issueTime_;
  case X509::CB_EXPIRE_TIME:
   return myCertSet.expireTime_;
  case X509::CB_PKEY_INFO:
   *((void**)cbData.pOut) = (void*)reinterpret_cast<const void*>(myCertSet.subPubKey_.pPubKey);
   if (myCertSet.subPubKey_.nEccGroup) return OID_ECCGROUP_SECP256R1;
   else return OID_PUBKEY_RSA;
   break;
  case X509::CB_KEY_USAGE:
   if (myCertSet.subPubKey_.pPubKey == myCertSet.caKeyPair_.pPubKey) return (KEYUSAGE_DIGITALSIGNATURE | KEYUSAGE_KEYCERTSIGN | KEYUSAGE_CRLSIGN);
   else return KEYUSAGE_DIGITALSIGNATURE;
  case X509::CB_BASIC_CONSTRAINT:
   return 1; //(myCertSet.subPubKey_.pPubKey == myCertSet.caKeyPair_.pPubKey); // CA:TRUE only for ROOT certificates
  case X509::CB_SUBJECT_ALTNAME:
   {
    uint32_t n                   = myCertSet.n_;
    *((const char**)cbData.pOut) = myCertSet.altNames_[n];
    if (myCertSet.altNames_[n])
    {
     myCertSet.n_++;
     return 1;
    }
    else
    {
     myCertSet.n_ = 0;
     return 0;
    }
   }
   break;
  case X509::CB_SIGN:
   if (myCertSet.caKeyPair_.nEccGroup)
   {
    // Generate a ECC signature using the input cbData.pIn of 32 bytes.
    P256::ECDSign sig;
    NN            secKey;
    secKey.bytesIn(myCertSet.caKeyPair_.pPriKey);
    uchar nc[32];
    {
     const CIPHER& sha(myCertSet.cset_.sha256);
     CTX           ctx;
     sha.Hash((const uchar*)cbData.pIn, 32, nc);
     sha.Init(&ctx, NULL);
     sha.Input(&ctx, myCertSet.caKeyPair_.pPriKey, 32);
     sha.Input(&ctx, nc, 32);
     sha.Digest(&ctx, nc);
    }
    sig.Sign((const uchar*)cbData.pIn, nc, secKey);
    uchar* pMsg = (uchar*)cbData.pOut;
    sig.OutR(pMsg);
    pMsg += 0x20;
    sig.OutS(pMsg);
    pMsg += 0x20;
    return (pMsg - (uchar*)cbData.pOut);
   }
   else
   {
    memcpy((pu8)cbData.pOut + 256 - 32, cbData.pIn, 32);
    myCertSet.cset_.rsa.RsaDecrypt((pu8)cbData.pOut, myCertSet.caKeyPair_.pPubKey, myCertSet.caKeyPair_.pPriKey, 256);
    return 256;
   }
  default:
   break;
 }
 return 0;
}


// int certGen(const CIPHERSET& cipherSet, const X509::X509NAME& name, const char* outName);
// https://letsencrypt.org/2018/04/04/sct-encoding.html
// $ openssl x509 -noout -text -inform der -in Downloads/031f2484307c9bc511b3123cb236a480d451

const uint8_t* certGen(
    const CIPHERSET*      cipherSet,
    const KEYPAIR*        pCaKeyPair, // Issuer kerpair including public and private key.
    const KEYPAIR*        pSubPubKey, // The private key portion is not set and not used.
    const X509::X509NAME* issuer, const X509::X509NAME* subject, const char* altNames[], uint32_t issueTime, uint32_t expireTime, uint64_t serial_num)
{
 static u8 tmp[2048];
 u8*       p0 = tmp;
 u8*       p  = p0;

 MyCertSet myCertSet(*cipherSet, *pCaKeyPair, *pSubPubKey, *issuer, *subject, altNames, issueTime, expireTime, serial_num);

 memset(tmp, 0, sizeof(tmp));

 uint nSize = 0;
 {
  X509v3 cer(p, myCallback, &myCertSet);
  nSize = cer.size();
 }
 return tmp;
}

#ifdef __cplusplus
} // extern "C"
#endif //__cplusplus


#endif // CERT_GEN_INCLUDED_
