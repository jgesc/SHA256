/**

=== SHA-256 Hashing ===

SHA-256 algorithm implementation following SHA-2 standard, 
approved as FIPS 180-4 standard on October 2008.

This implementation uses Big-Endian, as stated on the above standard.

**/

#ifndef __SHA256_H__
#define __SHA256_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//Datatypes
#define BYTE unsigned char
#define WORD unsigned int

/**
BYTE* sha256(BYTE* input, size_t len);

Returns the 256-bit long (32 bytes) SHA256 hash of 
the 'len' bytes long 'input'.
**/
BYTE* sha256(BYTE* input, size_t len);

#endif