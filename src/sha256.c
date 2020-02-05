/**

=== SHA-256 Hashing ===

SHA-256 algorithm implementation following SHA-2 standard, 
approved as FIPS 180-4 standard on October 2008.

This implementation uses Big-Endian, as stated on the above standard.

**/


#include "sha256.h"

//Helper macros
#define rot(a, n) ((a >> n) | (a << (32 - n))) //Rotate right

//SHA256 functions
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x) (rot((x), 2) ^ rot((x), 13) ^ rot((x), 22))
#define SIGMA1(x) (rot((x), 6) ^ rot((x), 11) ^ rot((x), 25))
#define sigma0(x) (rot((x), 7) ^ rot((x), 18) ^ ((x) >> 3))
#define sigma1(x) (rot((x), 17) ^ rot((x), 19) ^ ((x) >> 10))

//SHA-256 initial hash values
const WORD H0[] = 
{ 
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 
};
//SHA-256 constant values
const WORD K[] = 
{
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

BYTE* sha256(BYTE* input, size_t len)
{
	///Variable declaration

	size_t N; //Number of blocks

	//Used to read as Big-Endian
	struct byte4 {
		BYTE b0, b1, b2, b3;
	} tmp1, tmp2;
	
	//Padding values
	size_t l;
	WORD k;
	//Iterators
	int i, j;
	//Intermediate hash value
	WORD** H;
	//Expanded message blocks
	WORD W[64];
	//Registers
	WORD a, b, c, d, e, f, g, h, t1, t2;
	//Message divided into 512-bit blocks
	WORD **M; //Accesses each block as 4 byte segments
	BYTE * _M; //Message the algorithm will work with
	//Result
	BYTE* hash;
	
	
	///SHA256 algorithm
	
	//Preprocessing
	//Padding
	k = 64 - (len + 9) % 64;
	//exit(0);
	_M = calloc(len + 9 + k, 1);
	memcpy(_M, input, len);
	//Add '1' bit
	_M[len] = 0x80;
	//Write the message length in bits to the last 8 bytes using Big-Endian
	l = len * 8;
	for(i = 0; i < 8; i++) 
		_M[len + k + 1 + i] = ((unsigned char *)(&l))[7-i];
	
	//Divide blocks
	N = (len + 9 + k) / 64; //Total number of blocks
	//Block accessing
	M = malloc(N * sizeof(WORD *));
	for(i = 0; i < N; i++)
		M[i] = (WORD *)(_M + i * 64);

	//Allocate memory for intermediate hash values
	H = malloc((N + 1) * sizeof(WORD*));
	H[0] = (WORD*)&H0;
	for(i = 1; i <= N; i++)
		H[i] = malloc(8 * sizeof(WORD*));


	//Main loop
	//Process input as 512 bits blocks
	for(i = 1; i <= N; i++)
	{
		//SHA-256 message schedule
		for(j = 0; j < 16; j++) 
		{
			//Read as Big-Endian
			tmp1 = *((struct byte4*)(&(M[i - 1][j])));
			tmp2.b0 = tmp1.b3;
			tmp2.b1 = tmp1.b2;
			tmp2.b2 = tmp1.b1;
			tmp2.b3 = tmp1.b0;
			
			W[j] = *((WORD *)(&tmp2));
		}
		for(j = 16; j < 64; j++) 
			W[j] = sigma1(W[j - 2]) + W[j - 7] + 
				   sigma0(W[j - 15]) + W[j - 16];
		
		//Initialize registers with the (i - 1)st hash value
		a = H[i - 1][0];
		b = H[i - 1][1];
		c = H[i - 1][2];
		d = H[i - 1][3];
		e = H[i - 1][4];
		f = H[i - 1][5];
		g = H[i - 1][6];
		h = H[i - 1][7];

		//Apply SHA-256 compression function
		for(j = 0; j < 64; j++)
		{
			t1 = h + SIGMA1(e) + Ch(e, f, g) + K[j] + W[j];
			t2 = SIGMA0(a) + Maj(a, b, c);
			h = g;
			g = f;
			f = e;
			e = d + t1;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;
		}

		//Compute ith intermediate hash value
		H[i][0] = a + H[i - 1][0];
		H[i][1] = b + H[i - 1][1];
		H[i][2] = c + H[i - 1][2];
		H[i][3] = d + H[i - 1][3];
		H[i][4] = e + H[i - 1][4];
		H[i][5] = f + H[i - 1][5];
		H[i][6] = g + H[i - 1][6];
		H[i][7] = h + H[i - 1][7];
	}
	
	hash = malloc(32);
	
	//Copy the result as Little-Endian
	for(i = 0; i < 8; i++)
		for(j = 0; j < 4; j++)
			hash[i * 4 + j] = ((BYTE *)(&(H[N][i])))[3 - j];
	
	//Free memory
	free(_M);
	for(i = 1; i <= N; i++)
		free(H[i]);
	free(H);
	
	return hash;
}