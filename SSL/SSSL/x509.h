#ifndef X509_H_INCLUDED
#define X509_H_INCLUDED

#include "asn.h"
#include "../../include/cert/oid.h"

namespace X509
{

#define KEYUSAGE_DIGITALSIGNATURE 0x80 // digitalSignature(0),
#define KEYUSAGE_NONREPUDIATION   0x40 // nonRepudiation(1), --recent editions of X.509 have renamed this bit to contentCommitment
#define KEYUSAGE_KEYENCIPHERMENT  0x20 // keyEncipherment(2),
#define KEYUSAGE_DATAENCIPHERMENT 0x10 // dataEncipherment(3),
#define KEYUSAGE_KEYAGREEMENT     0x08 // keyAgreement(4),
#define KEYUSAGE_KEYCERTSIGN      0x04 // keyCertSign(5),
#define KEYUSAGE_CRLSIGN          0x02 // cRLSign(6),
#define KEYUSAGE_ENCIPHERONLY     0x01 // encipherOnly(7),
                                       // decipherOnly(8)     // ??????????????????????

// enum ALG {
//     ALG_SHA256 = 0,
// };

enum x509CB
{
 CB_ALGORITHM        = 0,
 CB_SERIAL           = 1,
 CB_HASH             = 2,
 CB_ISSUER_NAME      = 3,
 CB_SUBJECT_NAME     = 4,
 CB_PKEY_INFO        = 5,
 CB_ISSUE_TIME       = 6,
 CB_EXPIRE_TIME      = 7,
 CB_SIGN             = 8,
 CB_KEY_USAGE        = 9,
 CB_BASIC_CONSTRAINT = 10,
 CB_SUBJECT_ALTNAME  = 11,
};
//===================================================================================================
struct CB_DATA
{
 x509CB      eType;
 const void* pIn;
 uint        nInSize;
 void*       pOut;
};
//===================================================================================================
struct X509NAME
{
 const char* country;
 const char* state;
 const char* local;
 const char* company;
 const char* unitname;
 const char* commonname;

 size_t totalSize() const
 {
  size_t n = 0, i = 0;
  if (country)
  {
   for (i = 0; country[i]; i++);
   n += i;
   n += 11;
  }
  if (state)
  {
   for (i = 0; state[i]; i++);
   n += i;
   n += 11;
  }
  if (local)
  {
   for (i = 0; local[i]; i++);
   n += i;
   n += 11;
  }
  if (company)
  {
   for (i = 0; company[i]; i++);
   n += i;
   n += 11;
  }
  if (unitname)
  {
   for (i = 0; unitname[i]; i++);
   n += i;
   n += 11;
  }
  if (commonname)
  {
   for (i = 0; commonname[i]; i++);
   n += i;
   n += 11;
  }
  return n;
 }
};

typedef uint (*X509Callback)(void* context, const CB_DATA& cbData);
//===================================================================================================
class X509v3: public ASN::Seq2
{
 public:
 // RFC5288 for X509 v3 digital certificate https://tools.ietf.org/html/rfc5280
 X509v3(pu8& s, X509Callback cb, void* ctx) : Seq2(s)
 {
  CB_DATA cbData;
  cbData.eType   = x509CB(0);
  cbData.nInSize = 0;
  cbData.pIn     = nullptr;
  cbData.pOut    = nullptr;

  // Obtain signature algorithm.
  cbData.eType = CB_ALGORITHM;
  OID eOid     = OID(cb(ctx, cbData));

  // Certificate  :: = SEQUENCE{
  cbData.eType = CB_HASH;
  cbData.pIn   = p_;
  //    tbsCertificate       TBSCertificate,
  {
   tbsCertificate TBSCertificate(p_, cb, ctx, eOid);
  }
  cbData.nInSize = p_ - pu8(cbData.pIn);

  //    signatureAlgorithm   AlgorithmIdentifier,
  {
   signatureAlgorithm AlgorithmIdentifier(p_, eOid);
  }

  u8 digest[32];
  cbData.pOut    = digest;
  cbData.nInSize = cb(ctx, cbData);
  u8     sign[256];
  pu8    p = sign;
  size_t n = SetOID(sign, OID_DIGEST_SHA256); // eOid
  n        = 256 - n - 32 - 11;
  for (size_t i = 0; i < n; i++) sign[i] = 0xFF;
  sign[0] = 0x00;
  sign[1] = 0x01;
  p       = sign + n;
  *p++    = 0x00;
  {
   ASN::Seq0 seq(p);
   {
    ASN::Seq0 s2(&seq);
    {
     ASN::Oid oid(s2, OID_DIGEST_SHA256);
    } // eOid
    {
     ASN::NullTag nullTag(s2);
    }
   }
   {
    ASN::Oct oct(seq);
    oct += 32;
   }
  }
  cbData.pIn     = digest;
  cbData.pOut    = sign;
  cbData.eType   = CB_SIGN;
  cbData.nInSize = cb(ctx, cbData);

  //    signatureValue       BIT STRING }
  {
   signatureValue SignatureValue(p_, sign, cbData.nInSize);
  }
 }
 //---------------------------------------------------------------------------------------------------
};
//===================================================================================================
// nSecs is number of seconds since 01/01 00:00:00 UTC
static uint SetUTC(u8* p, uint32_t nSecs)
{
 const uchar* p0 = p;
 uint         days, secs, n;
 uint         year, month, day, hour, minute, second;

 // Calculate time from 01/01/2000 00:00:00 UTC
 days = nSecs / 86400;
 secs = nSecs - (days * 86400);

 // Convert to baseline 01/01/2000 00:00:00 UTC
 days -= 10957; // Days between 01/01/1970 and 01/01/2000

 minute  = (secs / 60);
 second  = secs - (minute * 60);
 hour    = (minute / 60);
 minute -= (hour * 60);

 year   = (days / 1461);
 days  -= year * 1461;
 year <<= 2;

 if (days >= 60)
 {
  days -= 1;
  year += n  = (days / 365);
  days      -= n * 365;
  if (days >= 59) days += 2; // Pretend Feb is 30 days vs 28
 }

 month = (days * 12 + 7) / 367;
 day   = days - ((month * 367 + 5) / 12);
 month++;
 day++;

 // Now format the UTC string
 *p++ = '0' + (year / 10);
 *p++ = '0' + year - ((year / 10) * 10);
 *p++ = '0' + (month / 10);
 *p++ = '0' + month - ((month / 10) * 10);
 *p++ = '0' + (day / 10);
 *p++ = '0' + day - ((day / 10) * 10);
 *p++ = '0' + (hour / 10);
 *p++ = '0' + hour - ((hour / 10) * 10);
 *p++ = '0' + (minute / 10);
 *p++ = '0' + minute - ((minute / 10) * 10);
 *p++ = '0' + (second / 10);
 *p++ = '0' + second - ((second / 10) * 10);
 *p++ = 'Z';

 return (p - p0);
}
//===================================================================================================
class tbsCertificate: public ASN::Seq2
{
 public:
 tbsCertificate(pu8& s, X509Callback cb, void* ctx, OID eOid) : Seq2(s)
 {
  CB_DATA cbData;
  cbData.eType   = X509::x509CB(0);
  cbData.nInSize = 0;
  cbData.pIn     = nullptr;
  cbData.pOut    = nullptr;

  // TBSCertificate  :: = SEQUENCE{
  //     version[0]  EXPLICIT Version DEFAULT v1,
  {
   ASN::Version ver(p_);
  }

  //    serialNumber         CertificateSerialNumber,
  uint64_t serial_num = 0; // Obtain the serial number from callback
  cbData.eType        = CB_SERIAL;
  cbData.pOut         = &serial_num;
  cb(ctx, cbData);
  {
   ASN::Int ser(p_, serial_num);
  }

  //    signature            AlgorithmIdentifier
  {
   signatureAlgorithm AlgorithmIdentifier(p_, eOid);
  }

  //    issuer               Name,
  X509NAME issuer{nullptr, nullptr, nullptr, nullptr, nullptr, nullptr};
  cbData.eType = CB_ISSUER_NAME;
  cbData.pOut  = &issuer;
  cb(ctx, cbData);
  {
   x509Id issuerName(p_, issuer);
  }

  //    validity             Validity,
  uint32_t nIssueTime = 0, nExpireTime = 0;
  cbData.pOut  = nullptr;
  cbData.eType = CB_ISSUE_TIME;
  nIssueTime   = cb(ctx, cbData);
  cbData.eType = CB_EXPIRE_TIME;
  nExpireTime  = cb(ctx, cbData);
  {
   ASN::Seq0 timeStamp(p_);
   {
    {
     ASN::Utc issueTime(timeStamp);
     issueTime += SetUTC(issueTime, nIssueTime);
    }
    {
     ASN::Utc expireTime(timeStamp);
     expireTime += SetUTC(expireTime, nExpireTime);
    }
   }
  }

  //    subject              Name,
  X509NAME subject{nullptr, nullptr, nullptr, nullptr, nullptr, nullptr};
  cbData.eType = CB_SUBJECT_NAME;
  cbData.pOut  = &subject;
  cb(ctx, cbData);
  {
   x509Id subjectName(p_, subject);
  }

  //    subjectPublicKeyInfo SubjectPublicKeyInfo,
  const u8* pKey = nullptr;
  cbData.eType   = CB_PKEY_INFO;
  cbData.pOut    = &pKey;
  OID eType      = OID(cb(ctx, cbData));
  {
   ASN::PubKey pubKeyInfo(p_, eType, pKey);
  }

  //    issuerUniqueID[1]  IMPLICIT UniqueIdentifier OPTIONAL,
  //    --If present, version MUST be v2 or v3

  // Certificate extensions. http://www.oid-info.com/get/2.5.29
  {
   ASN::Ext extensions(p_);
   {
    ASN::Seq0 seq(extensions);
    {
     cbData.pIn = cbData.pOut = nullptr;
     cbData.nInSize           = 0;
     cbData.eType             = CB_KEY_USAGE;
     uint nKeyUsage           = cb(ctx, cbData);
     if (nKeyUsage)
     {
      ASN::Seq0 sq(&seq);
      {
       {
        ASN::Oid oid(sq, OID_X509V3_KEY_USAGE);
       }
       {
        ASN::Bool b(sq, true);
       }
       {
        ASN::Oct o(sq);
        {
         ASN::Bstr bs(o);
         *bs++ = u8(nKeyUsage);
        }
       }
      }
     }
     cbData.eType          = CB_BASIC_CONSTRAINT;
     uint nBasicConstraint = cb(ctx, cbData);
     if (nBasicConstraint)
     {
      ASN::Seq0 sq(&seq);
      {
       {
        ASN::Oid oid(sq, OID_X509V3_BASIC_CONSTRAINTS);
       }
       {
        ASN::Bool b(sq, true);
       }
       //{ASN::Oct  o(sq); {ASN::Seq0 s(o); {ASN::Bool b(s, true);  ASN::Int in(s, uint32_t(0)); }}}   // >>>	The extra ASN::Int in(s, uint32_t(0)); is not standard for a root CA and confuses OpenSSL.  INTEGER (pathLen) is optional and should only be present if you want to restrict the CA path length.
       {
        ASN::Oct o(sq);
        {
         ASN::Seq0 s(o);
         {
          ASN::Bool b(s, true);
         }
        }
       }
      }
     }
     const char* pAltName = nullptr;
     cbData.pOut          = &pAltName;
     cbData.eType         = CB_SUBJECT_ALTNAME;
     if (cb(ctx, cbData) && pAltName != nullptr)
     {
      ASN::Seq0 sq(&seq);
      {
       {
        ASN::Oid oid(sq, OID_X509V3_SUBJECT_ALTNAME);
       }
       {
        ASN::Bool b(sq, true);
       }
       {
        ASN::Oct o(sq);
        {
         ASN::Seq0 s(o);
         do {
          ASN::Altn dn(s, pAltName);
          pAltName = nullptr;
         } while (cb(ctx, cbData) && pAltName != nullptr);
        }
       }
      }
     }
    }
   }
  }
 }
};
//---------------------------------------------------------------------------------------------------
class signatureAlgorithm: public ASN::Seq0
{
 public:
 signatureAlgorithm(pu8& s, OID eOid) : Seq0(s)
 {
  {
   ASN::Oid oid(p_, eOid);
  }
  {
   ASN::NullTag nullTag(p_);
  }
 }
};
//---------------------------------------------------------------------------------------------------
class signatureValue
{
 public:
 signatureValue(pu8& s, const u8* pSign, size_t n)
 {
  if (n >= 256)
  {
   ASN::Bstr2 bstr(s);
   while (n-- > 0) *bstr++ = *pSign++;
  }
  else
  {
   ASN::Bstr bstr(s);
   {
    ASN::Seq0 seq(bstr);
    {
     ASN::Intb r(seq, pSign, 0x20);
    }
    {
     ASN::Intb s(seq, pSign + 0x20, 0x20);
    }
   }
  }
 }
};
//---------------------------------------------------------------------------------------------------
class x509Id: public ASN::Seq
{
 public:
 x509Id(pu8& s, const X509NAME& name) : Seq(s, name.totalSize())
 {
  {
   ASN::Set idSet(p_);
   {
    ASN::Seq0 sq(idSet);
    {
     {
      ASN::Oid oid(sq, OID_NAME_COUNTRY);
     }
     {
      ASN::Pstr pstr(sq, name.country);
     }
    }
   }
  }
  {
   ASN::Set idSet(p_);
   {
    ASN::Seq0 sq(idSet);
    {
     {
      ASN::Oid oid(sq, OID_NAME_STATE);
     }
     {
      ASN::Pstr pstr(sq, name.state);
     }
    }
   }
  }
  {
   ASN::Set idSet(p_);
   {
    ASN::Seq0 sq(idSet);
    {
     {
      ASN::Oid oid(sq, OID_NAME_LOCAL);
     }
     {
      ASN::Pstr pstr(sq, name.local);
     }
    }
   }
  }
  {
   ASN::Set idSet(p_);
   {
    ASN::Seq0 sq(idSet);
    {
     {
      ASN::Oid oid(sq, OID_NAME_ORG);
     }
     {
      ASN::Pstr pstr(sq, name.company);
     }
    }
   }
  }
  {
   ASN::Set idSet(p_);
   {
    ASN::Seq0 sq(idSet);
    {
     {
      ASN::Oid oid(sq, OID_NAME_UNIT);
     }
     {
      ASN::Pstr pstr(sq, name.unitname);
     }
    }
   }
  }
  {
   ASN::Set idSet(p_);
   {
    ASN::Seq0 sq(idSet);
    {
     {
      ASN::Oid oid(sq, OID_NAME_COMMON);
     }
     {
      ASN::Pstr pstr(sq, name.commonname);
     }
    }
   }
  }
 }
};
//---------------------------------------------------------------------------------------------------
//===================================================================================================

} // namespace X509

#endif // X509_H_INCLUDED
