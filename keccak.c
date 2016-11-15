#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "keccak.h"

/* Useful macros */
/* Rotate a 64b word to the left by n positions */
#define ROL64(a, n) ((((n)%64) != 0) ? ((((uint64_t)a) << ((n)%64)) ^ (((uint64_t)a) >> (64-((n)%64)))) : a)
#define mapping(x, y) (x + (y*5))
unsigned long RC[] =
{
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808A,
	0x8000000080008000,
	0x000000000000808B,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008A,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000A,
	0x000000008000808B,
	0x800000000000008B,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800A,
	0x800000008000000A,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008
};


unsigned long RhoOffset[5][5] = {
	{0, 36, 3, 41, 18},
	{1, 44, 10, 45, 2},
	{62, 6, 43, 15, 61},
	{28, 55, 25, 21, 56},
	{27, 20, 39, 8, 14}
};

unsigned int mod (int a, int b)
{
	int ret = a % b;
    if(ret < 0)
    	ret+=b;
    return ret;
}


/// This function is hidden because it is used only within this file
void r_ound(uint64_t * A, unsigned int rnd);
void Round(uint64_t * A, unsigned int rnd);
void printStateArrayInverted(uint64_t * A);
void printStateArray(uint64_t * A);
void keccak_pi(uint64_t *A);
void keccak_pi_1(uint64_t *A);
/* Function prototypes */
unsigned char rc(unsigned int t);

/*****************************************************************************
 * @brief: This set of functions prints the content of a generic state array
 * @author: Jacopo Bufalino - jacopobufalino@gmail.com
 * @date: 2016/13/10 
 * @return: void 
 * @arg: inpunt state array
 * @note: Use them just to debug the code
 *
 *****************************************************************************/
void printStateArray(uint64_t * A)
{

	int i;
	for (i = 0; i < 25; i++) {
		if (i % 2 == 0)
			printf("\n");
		printf("%.16llx", A[i]);


	}
	printf("\n");
}
void printStateArrayInverted(uint64_t * A)
{
	unsigned char *ptr = (unsigned char *)A;
	int i;
	for (i = 0; i < 200; i++) {

		if (i % 16 == 0)
			printf("\n");
		printf("%.2X ", ptr[i]);


	}
	printf("\n");
}
/*****************************************************************************
 * @brief: The sequence of step mappings that is iterated in the calculation of
 * a KECCAK-p* permutation
 * @author: Jacopo Bufalino - jacopobufalino@gmail.com
 * @date: 2016/13/10
 * @return: updated state array
 * @arg: state array and number of round
 * @note: This function contains all steps to perform the permutation.
 *
 *****************************************************************************/
void Round(uint64_t * A, unsigned int rnd)
{

	unsigned int n_start = 12 + 2*6 -rnd;
	unsigned int n_end = 12 +(2*6);
	unsigned int x,y;

	//pi^(-1)
	keccak_pi_1(A);


	for (unsigned int i = n_start; i < n_end; i++) {
		trace(printf("\n+++Round %d+++\n", i));
		r_ound(A, i);
	}

	//pi
	keccak_pi(A);




}
void r_ound(uint64_t * A, unsigned int rnd)
{
	uint64_t C[MOD], B[MOD * MOD], D[MOD];
	uint8_t x, y;

	/* Initialization */
	bzero(C, sizeof(C));
	bzero(D, sizeof(D));
	bzero(B, sizeof(B));

	trace(printStateArrayInverted(A));
	///theta step
	/*

	   C[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4]
	   forall x in 0…4

	   D[x] = C[x-1] xor rot(C[x+1],1),                              
	   forall x in 0…4

	   A[x,y] = A[x,y] xor D[x],                           
	   forall (x,y) in (0…4,0…4)

*/
	trace(printf("After theta:\n"));

	for (x = 0; x < MOD; x++) {
		C[x] = A[indexOf(0, x)] ^ A[indexOf(1, x)] ^ A[indexOf(2, x)]
			^ A[indexOf(3, x)] ^ A[indexOf(4, x)];
	}
	for (x = 0; x < MOD; ++x) {

		D[x] = C[(x + 4) % MOD] ^ ROL64(C[(x + 1) % MOD], 1);
		for (y = 0; y < MOD; ++y)
			A[indexOf(y, x)] = A[indexOf(y, x)] ^ D[x];


	}

	trace(printStateArrayInverted(A));


	///rho step
	/*
	   B[y,x] = rot(A[x,y], r[x,y])
	   forall (x,y) in (0…4,0…4)
	   */
	/*trace(printf("After rho:\n"));

	  for (x = 0; x < 5; x++) 
	  for (y = 0; y < 5; y++) 
	  B[indexOf(y, x)] =
	  ROL64(A[indexOf(y, x)], RhoOffset[x][y]);

	  trace(printStateArrayInverted(B));
	  */

	///pi step

	/*
	   B[y,x] =  B[y,2*x+3*y] forall (x,y) in (0…4,0…4)

*/
	trace(printf("After pi:\n"));

	for (x = 0; x < 5; ++x)
		for (y = 0; y < 5; ++y) {
			B[indexOf(2 * x + 3 * y, y)] =
				ROL64(A[indexOf(y, x)], RhoOffset[x][y]);

		}

	trace(printStateArrayInverted(B));

	///chi step

	/*

	   A[x,y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y])
	   forall (x,y) in (0…4,0…4)

*/
	trace(printf("After chi:%c\n", 0));

	for (x = 0; x < 5; ++x)
		for (y = 0; y < 5; ++y)
			A[indexOf(y, x)] = B[indexOf(y, x)] ^
				((~B[indexOf(y, x + 1)]) &
				 B[indexOf(y, x + 2)]);

	trace(printStateArrayInverted(A));

	///iota step
	/*

	   A[0,0] = A[0,0] xor RC

*/
	trace(printf("After iota:%c\n", 0));
	A[indexOf(0, 0)] = A[indexOf(0, 0)] ^ RC[rnd%25];

	trace(printStateArrayInverted(A));





}
void keccak_pi(uint64_t *A){

	unsigned int x = 1, y = 0; 
	unsigned int x2 = 0, y2 = 0; 
	unsigned int posInitial = 0; 
	unsigned int posInitialFlag = mapping (x, y); //index of (1, 0)
	unsigned int posNext = 0; 
	uint64_t s1 = A[posInitialFlag]; //save the element in position number one 

	/* For all the element, perform the operation: A[x,y] = A[(x+3y)mod 5, x] */
	/* Since this operation should be performed for all the values of x and y 
	 * it is necessary to initialize x or y to a value different to 0,
	 * otherwise in each iteraction of the while loop above 
	 * will not change the values of x and y ( mapping (0,0) == (0,0) ).
	 * If (x, y) are initialized to (1, 0), the element at this index
	 * will be changed, thus it is necessary to store its initial value 
	 * somewhere (in s1), in order to assign it later to another element
	 * when required.
	 */
	while (posNext != posInitialFlag){
		posInitial = mapping (x, y); //find the position in the string for the left element of the operation
		y2 = x; //y index for the right element of the operation
		x2 = mod ((x + 3*y), 5); //x index for the right element of the operation
		posNext = mapping (x2, y2); //find the position in the string for the right element of the operation

		/* The element is position 1 has been modified by previous iteraction, so we cannot perform 
		 * a normal assignment operation, but we need to assign the old value of the element s[1],
		 * previous saved in s1 */
		if(posNext != posInitialFlag) 
			A[posInitial] = A[posNext]; //the operation is normally performed
		else A[posInitial] = s1;  
		/* Changing x and y value for the next iteration */ 
		x = x2;
		y = y2;
	} 





}

void keccak_pi_1(uint64_t *A){

	unsigned int x = 1, y = 0; 
	unsigned int x2 = 0, y2 = 0; 
	unsigned int posInitial = 0; 
	unsigned int posInitialFlag = mapping (x, y); //index of (1, 0)
	unsigned int posNext = 0; 
	uint64_t s1 = A[posInitialFlag]; //save the element in position number one 

	/* For all the element, perform the operation: A[x,y] = A[(x+3y)mod 5, x] */
	/* Since this operation should be performed for all the values of x and y 
	 * it is necessary to initialize x or y to a value different to 0,
	 * otherwise in each iteraction of the while loop above 
	 * will not change the values of x and y ( mapping (0,0) == (0,0) ).
	 * If (x, y) are initialized to (1, 0), the element at this index
	 * will be changed, thus it is necessary to store its initial value 
	 * somewhere (in s1), in order to assign it later to another element
	 * when required.
	 */
	while (posNext != posInitialFlag){
		posInitial = mapping (x, y); //find the position in the string for the left element of the operation
		x2 = y; //y index for the right element of the operation
		y2 = mod ((2*x + 3*y), 5); //x index for the right element of the operation
		posNext = mapping (x2, y2); //find the position in the string for the right element of the operation

		/* The element is position 1 has been modified by previous iteraction, so we cannot perform 
		 * a normal assignment operation, but we need to assign the old value of the element s[1],
		 * previous saved in s1 */
		if(posNext != posInitialFlag) 
			A[posInitial] = A[posNext]; //the operation is normally performed
		else A[posInitial] = s1;  
		/* Changing x and y value for the next iteration */ 
		x = x2;
		y = y2;
	} 





}



/* Perform the KECCAK-p*[b, n_r] algorithm
 *
 * S  - the input bit string
 * b  - the length of the input string in bits
 * nr - the number of rounds
 * l  - the value of l associated with b (log2(b/25))
 *
 * Returns a pointer to the output bit string
 */

unsigned char *keccak_p_star(unsigned char *S, unsigned long b, int nr, int l)
{
	/* Implement this function using the code you wrote for Assignment 1.
	 * You will need to implement one extra function, the permutation
	 * pi^(-1) (the inverse of pi) described in Section 2.1 of the Ketje
	 * document and Section 8 of the Assignment 2 instructions.
	 */

	unsigned char *output_string = calloc (200,sizeof(unsigned char));
	memcpy(output_string, S, 200 * sizeof(char));
	
	printf("******************** STATE BEFORE KECCAK ***************\n\n");
	for (int i = 0 ; i < 200 ; i++)
		printf("%.2x ",output_string[i]);
	printf("\n\n");	
	Round((uint64_t*) output_string,nr);

	printf("*****************STATE AFTER KECCAK**********************\n\n");
	for (int i = 0 ; i < 200 ; i++)
		printf("%.2x ",output_string[i]);
	printf("\n\n");	

	return output_string;
}

/* Copy n bits from a buffer to another.
 *
 * dst   - the destination buffer, allocated by the caller
 * dst_o - the bit offset in the destination buffer
 * src   - the source buffer, allocated by the caller
 * src_o - the bit offset in the source buffer
 * n     - the number of bits to copy
 *
 * n does not need to be a multiple of 8.
 * dst and src must be at least ceiling(n/8) bytes long.
 */
void cpynbits(unsigned char *dst, unsigned int dst_o,
		const unsigned char *src, unsigned int src_o, unsigned int n)
{
	unsigned int v;
	unsigned int s_bit_cursor, s_byte_cursor, d_bit_cursor, d_byte_cursor;
	// Initialise cursors
	s_byte_cursor = src_o / 8;
	s_bit_cursor = src_o % 8;
	d_byte_cursor = dst_o / 8;
	d_bit_cursor = dst_o % 8;

	// If both cursors are byte-aligned, and n is a multiple of 8 bits
	if (s_bit_cursor == 0 && d_bit_cursor == 0 && n % 8 == 0) {
		// Just copy n/8 bytes byte by byte from src to dst
		for (unsigned int i = 0; i < n / 8; i++) {
			dst[d_byte_cursor + i] = src[s_byte_cursor + i];
		}
	} else {
		// Copy n bits bit by bit from src to dst
		for (unsigned long i = 0; i < n; i++) {
			// Get the bit
			v = ((src[s_byte_cursor] >> s_bit_cursor) & 1);
			// Set the bit
			dst[d_byte_cursor] ^=
				(-v ^ dst[d_byte_cursor]) & (1 << d_bit_cursor);
			// Increment cursors
			if (++s_bit_cursor == 8) {
				s_byte_cursor++;
				s_bit_cursor = 0;
			}
			if (++d_bit_cursor == 8) {
				d_byte_cursor++;
				d_bit_cursor = 0;
			}
		}
	}
}

/* Concatenate two bit strings (X||Y)
 *
 * Z     - the output bit string. The array is allocated by this function: the
 *         caller must take care of freeing it after use.
 * X     - the first bit string
 * X_len - the length of the first string in bits
 * Y     - the second bit string
 * Y_len - the length of the second string in bits
 *
 * Returns the length of the output string in bits. The length in Bytes of the
 * output C array is ceiling(output_bit_len/8).
 */
unsigned long concatenate(unsigned char **Z, const unsigned char *X,
		unsigned long X_len, const unsigned char *Y,
		unsigned long Y_len)
{
	/* The bit length of Z: the sum of X_len and Y_len */
	unsigned long Z_bit_len = X_len + Y_len;
	/* The byte length of Z:
	 * the least multiple of 8 greater than X_len + Y_len */
	unsigned long Z_byte_len = (Z_bit_len / 8) + (Z_bit_len % 8 ? 1 : 0);
	// Allocate the output string and initialize it to 0
	*Z = calloc(Z_byte_len, sizeof(unsigned char));
	if (*Z == NULL)
		return 0;
	// Copy X_len bits from X to Z
	cpynbits(*Z, 0, X, 0, X_len);
	// Copy Y_len bits from Y to Z
	cpynbits(*Z, X_len, Y, 0, Y_len);

	return Z_bit_len;
}

/* Concatenate the 00, 01, 10, or 11 bit string to a given bit string
 * e.g. (X||00), (X||01), (X||10), (X||11)
 * Due to the KECCAK bit string representation, the bit strings are represented
 * as bytes respectively as:
 *       00 -> 0x00
 *       01 -> 0x02
 *       10 -> 0x01
 *       11 -> 0x03
 *
 * Z     - the output bit string. The array is allocated by this function: the
 *         caller must take care of freeing it after use.
 * X     - the bit string
 * X_len - the length of the string in bits
 *
 * Returns the length of the output string in bits. The length in Bytes of the
 * output C array is ceiling(output_bit_len/8).
 */
unsigned long concatenate_00(unsigned char **Z, const unsigned char *X,
		unsigned long X_len)
{
	unsigned char zeroes[] = { 0x00 };
	return concatenate(Z, X, X_len, zeroes, 2);
}

unsigned long concatenate_01(unsigned char **Z, const unsigned char *X,
		unsigned long X_len)
{
	unsigned char zeroone[] = { 0x02 };
	return concatenate(Z, X, X_len, zeroone, 2);
}

unsigned long concatenate_10(unsigned char **Z, const unsigned char *X,
		unsigned long X_len)
{
	unsigned char onezero[] = { 0x01 };
	return concatenate(Z, X, X_len, onezero, 2);
}

unsigned long concatenate_11(unsigned char **Z, const unsigned char *X,
		unsigned long X_len)
{
	unsigned char ones[] = { 0x03 };
	return concatenate(Z, X, X_len, ones, 2);
}

/* Performs the pad10*1(x, m) algorithm
 *
 * P - the output bit string. The array is allocated by this function: the
 *     caller must take care of freeing it after use.
 * x - the alignment value
 * m - the existing string length in bits
 *
 * Returns the length in bits of the output bit string.
 */
unsigned long pad10x1(unsigned char **P, unsigned int x, unsigned int m)
{
	/* 1. j = (-m-2) mod x */
	long j = (2 * x - 2 - (m % x)) % x;
	/* 2. P = 1 || zeroes(j) || 1 */
	// Compute P bit and byte length
	unsigned long P_bit_len = 2 + j;
	unsigned long P_byte_len = (P_bit_len / 8) + (P_bit_len % 8 ? 1 : 0);
	// Allocate P and initialize to 0
	*P = calloc(P_byte_len, sizeof(unsigned char));
	if (*P == NULL)
		return 0;
	// Set the 1st bit of P to 1
	(*P)[0] |= 1;
	// Set the last bit of P to 1
	(*P)[P_byte_len - 1] |= (1 << (P_bit_len - 1) % 8);

	return P_bit_len;
}

/* Perform the rc(t) algorithm
 *
 * t - the number of rounds to perform in the LFSR
 *
 * Returns a single bit stored as the LSB of an unsigned char.
 */
unsigned char rc(unsigned int t)
{
	unsigned int tmod = t % 255;
	/* 1. If t mod255 = 0, return 1 */
	if (tmod == 0)
		return 1;
	/* 2. Let R = 10000000
	 *    The LSB is on the right: R[0] = R &0x80, R[8] = R &1 */
	unsigned char R = 0x80, R0;
	/* 3. For i from 1 to t mod 255 */
	for (unsigned int i = 1; i <= tmod; i++) {
		/* a. R = 0 || R */
		R0 = 0;
		/* b. R[0] ^= R[8] */
		R0 ^= (R & 1);
		/* c. R[4] ^= R[8] */
		R ^= (R & 0x1) << 4;
		/* d. R[5] ^= R[8] */
		R ^= (R & 0x1) << 3;
		/* e. R[6] ^= R[8] */
		R ^= (R & 0x1) << 2;
		/* Shift right by one */
		R >>= 1;
		/* Copy the value of R0 in */
		R ^= R0 << 7;
	}
	/* 4. Return R[0] */
	return R >> 7;
}
