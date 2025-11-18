#ifndef _ENDIAN_H_INCLUDED_6_27_2014_
#define _ENDIAN_H_INCLUDED_6_27_2014_

typedef uint8_t uchar;
typedef uint32_t uint;

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/******************************************************************************
* Function:     Int2Byte
*
* Description:  Native endian 4 bytes integers to network order bytes.
*
* Returns:      None
******************************************************************************/
void Int2Byte(const uint* pIn, uchar* pOut, uint nLen)
{
    for ( ; nLen--; ) {
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
void Byte2Int(const uchar* pIn, uint* pOut, uint nLen)
{
    for ( ; nLen--; ) {
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
void Int2LByte(const uint* pIn, uchar* pOut, uint nLen)
{
    for ( ; nLen--; ) {
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
void LByte2Int(const uchar* pIn, uint* pOut, uint nLen)
{
    for ( ; nLen--; ) {
        uint    val;
        
        val  = ((uint)(*pIn++));
        val += ((uint)(*pIn++))<<8;
        val += ((uint)(*pIn++))<<16;
        val += ((uint)(*pIn++))<<24;
        *pOut++ = val;
    }
}

#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus


#endif //#ifndef _ENDIAN_H_INCLUDED_6_27_2014_
