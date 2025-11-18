#ifndef ASN_INCLUDED
#define ASN_INCLUDED
#pragma once

#include "oid.h"
#include "../../include/cert/asn.h"
#include "../../include/cert/oid.h"

typedef unsigned char  u8;
typedef unsigned char* pu8;

namespace ASN
{

// Tag classes
#define CLASS_MASK           0xC0 // Bits 8 and 7
#define CLASS_UNIVERSAL      0x00 // 0 = Universal (defined by ITU X.680)
#define CLASS_APPLICATION    0x40 // 1 = Application
#define CLASS_CONTEXT        0x80 // 2 = Context-specific
#define CLASS_PRIVATE        0xC0 // 3 = Private

// Encoding type
#define FORM_MASK            0x20 // Bit 6
#define FORM_PRIMITIVE       0x00 // 0 = primitive
#define FORM_CONSTRUCTED     0x20 // 1 = constructed

// Universal tags
#define TAG_MASK             0x1F // Bits 5 - 1
#define TAG_ZERO             0x00 // Constructed [0]
#define TAG_EOC              0x00 //  0: End-of-contents octets
#define TAG_BOOLEAN          0x01 //  1: Boolean
#define TAG_INTEGER          0x02 //  2: Integer
#define TAG_BITSTRING        0x03 //  2: Bit string
#define TAG_OCTETSTRING      0x04 //  4: Byte string
#define TAG_NULLTAG          0x05 //  5: NULL
#define TAG_OID              0x06 //  6: Object Identifier
#define TAG_OBJDESCRIPTOR    0x07 //  7: Object Descriptor
#define TAG_EXTERNAL         0x08 //  8: External
#define TAG_REAL             0x09 //  9: Real
#define TAG_ENUMERATED       0x0A // 10: Enumerated
#define TAG_EMBEDDED_PDV     0x0B // 11: Embedded Presentation Data Value
#define TAG_UTF8STRING       0x0C // 12: UTF8 string
#define TAG_SEQUENCE         0x10 // 16: Sequence/sequence of
#define TAG_SET              0x11 // 17: Set/set of
#define TAG_NUMERICSTRING    0x12 // 18: Numeric string
#define TAG_PRINTABLESTRING  0x13 // 19: Printable string (ASCII subset)
#define TAG_T61STRING        0x14 // 20: T61/Teletex string
#define TAG_VIDEOTEXSTRING   0x15 // 21: Videotex string
#define TAG_IA5STRING        0x16 // 22: IA5/ASCII string
#define TAG_UTCTIME          0x17 // 23: UTC time
#define TAG_GENERALIZEDTIME  0x18 // 24: Generalized time
#define TAG_GRAPHICSTRING    0x19 // 25: Graphic string
#define TAG_VISIBLESTRING    0x1A // 26: Visible string (ASCII subset)
#define TAG_GENERALSTRING    0x1B // 27: General string
#define TAG_UNIVERSALSTRING  0x1C // 28: Universal string
#define TAG_BMPSTRING        0x1E // 30: Basic Multilingual Plane/Unicode string

// X.509 spec: https://tools.ietf.org/html/rfc5280#section-4.1
#define TAG_V1               0x00 // 00: Version V1
#define TAG_V2               0x01 // 00: Version V2
#define TAG_V3               0x02 // 00: Version V3

#define INTEGER_TAG          (CLASS_UNIVERSAL | FORM_PRIMITIVE | TAG_INTEGER)
#define OID_TAG              (CLASS_UNIVERSAL | FORM_PRIMITIVE | TAG_OID)
#define SEQUENCE_TAG         (CLASS_UNIVERSAL | FORM_CONSTRUCTED | TAG_SEQUENCE)
#define NULL_TAG             (CLASS_UNIVERSAL | FORM_PRIMITIVE | TAG_NULLTAG)
#define BITSTRING_TAG        (CLASS_UNIVERSAL | FORM_PRIMITIVE | TAG_BITSTRING)
#define OCTETSTRING_TAG      (CLASS_UNIVERSAL | FORM_PRIMITIVE | TAG_OCTETSTRING)
#define SET_TAG              (CLASS_UNIVERSAL | FORM_CONSTRUCTED | TAG_SET)
#define PRINTABLE_STRING_TAG (CLASS_UNIVERSAL | FORM_PRIMITIVE | TAG_PRINTABLESTRING)
#define IA5STRING_TAG        (CLASS_UNIVERSAL | FORM_PRIMITIVE | TAG_IA5STRING)
#define UTF8STRING_TAG       (CLASS_UNIVERSAL | FORM_PRIMITIVE | TAG_UTF8STRING)

#define UTCTIME_TAG          (CLASS_UNIVERSAL | FORM_PRIMITIVE | TAG_UTCTIME)
#define GENTIME_TAG          (CLASS_UNIVERSAL | FORM_PRIMITIVE | TAG_GENERALIZEDTIME)

#define EXTENSION_TAG        (CLASS_CONTEXT | FORM_CONSTRUCTED | TAG_BITSTRING)
#define VERSION_TAG          (CLASS_CONTEXT | FORM_CONSTRUCTED | TAG_ZERO)
#define DNAME_TAG            (CLASS_CONTEXT | FORM_PRIMITIVE | 0x02)
//---------------------------------------------------------------------------------------------------
class Asn
{
 private:
 const pu8 po_;
 const pu8 p0_;

 protected:
 pu8& p_;

 public:

 Asn(const pu8& s) : po_(s), p0_(s), p_((pu8&)s) { }  // Constructor for already well formatted message

 Asn(pu8& s, u8 t, size_t n) : po_(s), p0_(s + 2 + (n >= 128) + (n >= 256)), p_(*s++ = t, *s++ = u8((n < 0x80) ? n : (n < 0x100 ? (*s++ = 0x81, n) : (*s++ = (n < 65536) ? 0x82 : u8(n >> 16), *s++ = u8(n >> 8), n))), s) { }  // Constructor to build message

 ~Asn()
 {
  if (po_ == p0_) return;
  size_t n = p_ - p0_;
  p0_[-1]  = u8(n);
  if (n > 65535) p0_[-3] = u8(n >> 16);
  if (n > 255) p0_[-2] = u8(n >> 8);
  if (n > 127) po_[1] = 0x7E + (p0_ - po_);
 }

 operator pu8&() const { return p_; }
 pu8&   operator&() const { return p_; }
 u8     type() const { return po_[0]; }
 size_t size() const
 {
  if (p0_ == po_) { return (po_[1] < 0x80) ? size_t(po_[1]) + 2 : (po_[1] < 0x82) ? size_t(po_[2]) + 3 : ((size_t(po_[2]) << 8) + po_[3] + 4); }
  else
  {
   size_t n = p_ - p0_;
   return (n + 2 + (n >= 128) + (n >= 256));
  }
 }

 private:
 Asn(const Asn& s); // Prevent copying.
};
//---------------------------------------------------------------------------------------------------
class Asn0
{
 private:
 const pu8 p0_;

 protected:
 pu8& p_;

 public:
 Asn0(pu8& s, u8 t) : p0_(s + 2), p_(*s++ = t, *s++ = 0x00, s) { }
 ~Asn0() { p0_[-1] = u8(p_ - p0_); }

 operator pu8&() const { return p_; }
 pu8&   operator&() const { return p_; }
 size_t size() const { return (p_ - p0_ + 2); }

 private:
 Asn0(const Asn& s); // Prevent copying.
};
//---------------------------------------------------------------------------------------------------
class Asn1
{
 private:
 const pu8 p0_;

 protected:
 pu8& p_;

 public:
 Asn1(pu8& s, u8 t) : p0_(s + 3), p_(*s++ = t, *s++ = 0x81, *s++ = 0x00, s) { }
 ~Asn1() { p0_[-1] = u8(p_ - p0_); }

 operator pu8&() const { return p_; }
 pu8&   operator&() const { return p_; }
 size_t size() const { return (p_ - p0_ + 3); }

 private:
 Asn1(const Asn1& s); // Prevent copying.
};
//---------------------------------------------------------------------------------------------------
class Asn2
{
 private:
 const pu8 p0_;

 protected:
 pu8& p_;

 public:
 Asn2(pu8& s, u8 t) : p0_(s + 4), p_(*s++ = t, *s++ = 0x82, *s++ = 0x00, *s++ = 0x00, s) { }
 ~Asn2()
 {
  size_t n = p_ - p0_;
  p0_[-2]  = u8(n >> 8);
  p0_[-1]  = u8(n);
 }

 operator pu8&() const { return p_; }
 pu8&   operator&() const { return p_; }
 size_t size() const { return (p_ - p0_ + 4); }

 private:
 Asn2(const Asn2& s); // Prevent copying.
};
//---------------------------------------------------------------------------------------------------
class Asn3
{
 private:
 const pu8 p0_;

 protected:
 pu8& p_;

 public:
 Asn3(pu8& s, u8 t) : p0_(s + 4), p_(*s++ = t, *s++ = 0x00, *s++ = 0x00, *s++ = 0x00, s) { }
 ~Asn3()
 {
  size_t n = p_ - p0_;
  p0_[-3]  = u8(n >> 16);
  p0_[-2] = u8(n >> 8), p0_[-1] = u8(n);
 }

 operator pu8&() const { return p_; }
 pu8&   operator&() const { return p_; }
 size_t size() const { return (p_ - p0_ + 4); }

 private:
 Asn3(const Asn2& s); // Prevent copying.
};
//---------------------------------------------------------------------------------------------------
class Int: public Asn0
{
 public:
 Int(pu8& s, uint32_t v) : Asn0(s, INTEGER_TAG)
 {
  if (v > 0x80000000) *p_++ = 0x00;
  if (v > 0x800000) *p_++ = u8(v >> 24);
  if (v > 0x8000) *p_++ = u8(v >> 16);
  if (v > 0x80) *p_++ = u8(v >> 8);
  *p_++ = u8(v);
 }

 Int(pu8& s, uint64_t v) : Asn0(s, INTEGER_TAG)
 {
  if (v >= 0x8000000000000000LLU) *p_++ = 0x00;
  if (v >= 0x80000000000000LLU) *p_++ = u8(v >> 56);
  if (v >= 0x800000000000LLU) *p_++ = u8(v >> 48);
  if (v >= 0x8000000000LLU) *p_++ = u8(v >> 40);
  if (v >= 0x80000000) *p_++ = u8(v >> 32);
  if (v >= 0x800000) *p_++ = u8(v >> 24);
  if (v >= 0x8000) *p_++ = u8(v >> 16);
  if (v >= 0x80) *p_++ = u8(v >> 8);
  *p_++ = u8(v);
 }
};
//---------------------------------------------------------------------------------------------------
class Intb: public Asn
{
 public:
 Intb(pu8& s, const u8* pI, size_t nLen) : Asn(s, INTEGER_TAG, nLen + (*pI > 0x7f))
 {
  if (*pI >= 0x80) *p_++ = 0x00;
  while (nLen-- > 0) *p_++ = *pI++;
 }
};
//---------------------------------------------------------------------------------------------------
class Seq: public Asn
{
 public:
 Seq(pu8& s, size_t n) : Asn(s, SEQUENCE_TAG, n) { }

 private:
 Seq(const Seq& s);
};
//---------------------------------------------------------------------------------------------------
class Seq0: public Asn0
{
 public:
 Seq0(pu8& s) : Asn0(s, SEQUENCE_TAG) { }

 private:
 Seq0(const Seq0& s);
};
//---------------------------------------------------------------------------------------------------
class Seq1: public Asn1
{
 public:
 Seq1(pu8& s) : Asn1(s, SEQUENCE_TAG) { }

 private:
 Seq1(const Seq1& s);
};
//---------------------------------------------------------------------------------------------------
class Seq2: public Asn2
{
 public:
 Seq2(pu8& s) : Asn2(s, SEQUENCE_TAG) { }

 private:
 Seq2(const Seq2& s);
};
//---------------------------------------------------------------------------------------------------
class Oid: public Asn0
{
 public:
 Oid(pu8& s, OID oid) : Asn0(s, OID_TAG) { p_ += SetOID(p_, (OID)oid); }

 private:
 Oid(const Seq2& s);
};
//---------------------------------------------------------------------------------------------------
class NullTag: public Asn0
{
 public:
 NullTag(pu8& s) : Asn0(s, NULL_TAG) { }

 private:
 NullTag(const Seq2& s);
};
//---------------------------------------------------------------------------------------------------
class Version: public Asn0
{
 public:
 Version(pu8& s) : Asn0(s, VERSION_TAG) { Int it(p_, uint32_t(TAG_V3)); }

 private:
 Version(const Seq2& s);
};
//---------------------------------------------------------------------------------------------------
class Utc: public Asn0
{
 public:
 Utc(pu8& s) : Asn0(s, UTCTIME_TAG) { }

 private:
 Utc(const Utc& s);
};
//---------------------------------------------------------------------------------------------------
class Set: public Asn0
{
 public:
 Set(pu8& s) : Asn0(s, SET_TAG) { }

 private:
 Set(const Set& s);
};
//---------------------------------------------------------------------------------------------------
class Oct: public Asn0
{
 public:
 Oct(pu8& s) : Asn0(s, OCTETSTRING_TAG) { }

 private:
 Oct(const Oct& s);
};
//---------------------------------------------------------------------------------------------------
class Ext: public Asn0
{
 public:
 Ext(pu8& s) : Asn0(s, EXTENSION_TAG) { }

 private:
 Ext(const Ext& s);
};
//---------------------------------------------------------------------------------------------------
class Bool: public Asn0
{
 public:
 Bool(pu8& s, bool b) : Asn0(s, TAG_BOOLEAN) { *p_++ = b ? 0xFF : 0x00; }

 private:
 Bool(const Bool& s);
};
//---------------------------------------------------------------------------------------------------
class Pstr: public Asn0
{
 public:
 Pstr(pu8& s, const char* p) : Asn0(s, PRINTABLE_STRING_TAG)
 {
  if (p == nullptr)
  {
   p_ -= 2;
   return;
  }
  while (*p) *p_++ = u8(*p++);
 }

 private:
 Pstr(const Pstr& s);
};
//---------------------------------------------------------------------------------------------------
class Altn: public Asn0
{
 public:
 Altn(pu8& s, const char* p) : Asn0(s, DNAME_TAG)
 {
  while (*p) *p_++ = u8(*p++);
 }

 private:
 Altn(const Altn& s);
};
//---------------------------------------------------------------------------------------------------
class Bstr: public Asn0
{
 public:
 Bstr(pu8& s) : Asn0(s, BITSTRING_TAG) { *p_++ = 0x00; } // Bitstream always starts with a 0x00 byte.
 void add(const u8* p, size_t n)
 {
  while (n-- > 0) *p_++ = *p++;
 }

 private:
 Bstr(const Bstr& s);
};
//---------------------------------------------------------------------------------------------------
class Bstr2: public Asn2
{
 public:
 Bstr2(pu8& s) : Asn2(s, BITSTRING_TAG) { *p_++ = 0x00; } // Bitstream always starts with a 0x00 byte.

 void add(const u8* p, size_t n)
 {
  while (n-- > 0) *p_++ = *p++;
 }

 private:
 Bstr2(const Bstr& s);
};
//---------------------------------------------------------------------------------------------------
class PubKey: public Seq
{
 public:
 PubKey(pu8& s, OID eType, const u8* p) : Seq(s, (eType == OID_PUBKEY_RSA) ? 0x101 : 0x59)
 {
  if (eType == OID_PUBKEY_RSA)
  {
   {
    Seq2 seq(p_);
    {
     Oid oidType(seq, OID_PUBKEY_RSA);
    }
    {
     NullTag nullTag(&seq);
    }
   }
   {
    Bstr2 bstr(p_);
    {
     Seq2 seq(bstr);
     {
      Intb it(seq, p, 256);
     }
     {
      Int e(seq, uint32_t(0x10001));
     }
    }
   }
  }
  else
  {
   {
    Seq2 seq(p_);
    {
     Oid oidType(seq, OID_PUBKEY_ECC);
    }
    {
     Oid oidType(seq, eType);
    }
   }
   {
    Bstr bstr(p_);
    *bstr++ = 0x04;
    bstr.add(p, 0x40);
   }
  }
 }

 private:
 PubKey(const Pstr& s);
};
//---------------------------------------------------------------------------------------------------
} // namespace ASN

#endif // ASN_INCLUDED
