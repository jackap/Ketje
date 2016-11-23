#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <strings.h>
#include "ketje.h"
#include "keccak.h"

/* Useful macros */
// Convert a bit length in the corresponding byte length, rounding up.
#define BYTE_LEN(x) ((x/8)+(x%8?1:0))

/* Perform the Ketje Major authenticated encryption operation on a message.
 *
 * cryptogram - the output buffer for the ciphertext, allocated by the caller.
 *              The buffer is the same size as the "data" plaintext buffer.
 * tag        - the output buffer for the tag, allocated by the caller.
 * t_len      - the requested tag length in bits.
 * key        - the key, provided by the caller.
 * k_len      - the key length in bits.
 * nonce      - the nonce, provided by the caller.
 * n_len      - the nonce length in bits.
 * data       - the plaintext, provided by the caller.
 * d_len      - the plaintext length in bits.
 * header     - the additional plaintext, provided by the caller.
 * h_len      - the additional plaintext length in bits.
 */

void ketje_mj_e(unsigned char *cryptogram,
		unsigned char *tag, unsigned int t_len,
		const unsigned char *key, unsigned int k_len,
		const unsigned char *nonce, unsigned int n_len,
		const unsigned char *data, unsigned long d_len,
		const unsigned char *header, unsigned long h_len)
{
	/* Ketje Major-specific parameters:
	 *   f        = KECCAK-p*[1600]
	 *   rho      = 256
	 * For all Ketje instances:
	 *   n_start  = 12
	 *   n_step   = 1
	 *   n_stride = 6
	 */
	trace(printf("Inside ketje\n"));
	/*Initialize the specific parameters */
	Duplex *D = DuplexInit(1600, 256, 12, 1, 6);
	//if (key == NULL) return;
	/*Call the MonkeyWrap function to encrypt data */
	MonkeyWrap(D, cryptogram, tag, t_len, key,
		   k_len, nonce, n_len, data, d_len, header, h_len);
/*
trace(printf("Calling Wrap again\n"));
MonkeyWrapWrap(D,cryptogram,tag,t_len,data,8,header,h_len);
trace(printf("Calling third time\n"));
unsigned char d0[2] = {0x99,0xba};
MonkeyWrapWrap(D,cryptogram,tag,t_len,d0,16,header,0);
trace(printf("Calling third time\n"));
unsigned char d1[4] = {0xdd,0xfe,0x7e,0x9f};
MonkeyWrapWrap(D,cryptogram,tag,t_len,d1,32,header,0);
trace(printf("Calling third time\n"));
unsigned char d2[7] = {0xc3,0xe4,0x64,0x85,0x05,0x26,0xa6};
MonkeyWrapWrap(D,cryptogram,tag,t_len,d2,56,header,0);
trace(printf("Calling third time\n"));
unsigned char d3[11] = {
0x4b, 0x6c, 0xec, 0x0d, 0x8d, 0xae, 0x2e, 0x4f, 0xcf, 0xf0, 0x70
};
MonkeyWrapWrap(D,cryptogram,tag,t_len,d3,88,header,0);
trace(printf("Calling third time\n"));
unsigned char d4[17] = {
0x17, 0x38, 0xb8, 0xd9, 0x59, 0x7a, 0xfa, 0x1b, 0x9b, 0xbc,
0x3c, 0x5d, 0xdd, 0xfe, 0x7e, 0x9f, 0x1f};
MonkeyWrapWrap(D,cryptogram,tag,t_len,d4,136,header,0);
trace(printf("Calling third time\n"));
unsigned char d5[26] = {
0xc9, 0xea, 0x6a, 0x8b, 0x0b,
0x2c, 0xac, 0xcd, 0x4d, 0x6e,
0xee, 0x0f, 0x8f, 0xb0, 0x30, 0x51, 0xd1,
0xf2, 0x72, 0x93, 0x13, 0x34, 0xb4, 0xd5, 0x55, 0x76
};
MonkeyWrapWrap(D,cryptogram,tag,t_len,d5,208,header,0);

trace(printf("Calling third time\n"));
unsigned char d6[40] = {
0xa5, 0xc6, 0x46, 0x67, 0xe7, 0x08, 0x88, 0xa9, 0x29, 0x4a,
0xca, 0xeb, 0x6b, 0x8c, 0x0c, 0x2d, 0xad, 0xce, 0x4e, 0x6f,
0xef, 0x10, 0x90, 0xb1, 0x31, 0x52, 0xd2, 0xf3, 0x73, 0x94,
0x14, 0x35, 0xb5, 0xd6, 0x56, 0x77, 0xf7, 0x18, 0x98, 0xb9,
};
MonkeyWrapWrap(D,cryptogram,tag,t_len,d6,320,header,0);
trace(printf("Calling third time\n"));
unsigned char header_0[6] = {
0x10, 0xa1, 0x32, 0xc3, 0x54, 0xe5
};
MonkeyWrapWrap(D,cryptogram,tag,t_len,d0,0,header_0,48);
trace(printf("Calling third time\n"));
unsigned char d7[18]= {
0xbf, 0xe0, 0x60, 0x81, 0x01, 0x22, 0xa2,
0xc3, 0x43, 0x64, 0xe4, 0x05, 0x85, 0xa6, 0x26, 0x47,
0xc7, 0xe8
};
unsigned char header_1[6] = {
0x22, 0xb3, 0x44, 0xd5, 0x66, 0xf7
};
MonkeyWrapWrap(D,cryptogram,tag,t_len,d7,144,header_1,48);

unsigned char d8[45]= {
0xd5, 0xf6, 0x76, 0x97, 0x17, 0x38, 0xb8, 0xd9, 0x59, 0x7a,
0xfa, 0x1b, 0x9b, 0xbc, 0x3c, 0x5d, 0xdd, 0xfe, 0x7e, 0x9f,
0x1f, 0x40, 0xc0, 0xe1, 0x61, 0x82, 0x02, 0x23, 0xa3, 0xc4,
0x44, 0x65, 0xe5, 0x06, 0x86, 0xa7, 0x27, 0x48, 0xc8, 0xe9,
0x69, 0x8a, 0x0a, 0x2b, 0xab};
unsigned char header_2[6] = {
0x3d, 0xce, 0x5f, 0xf0, 0x81, 0x12
};
MonkeyWrapWrap(D,cryptogram,tag,t_len,d8,360,header_2,48);

unsigned char header_3[14] = {
0x20, 0xb1,
0x42, 0xd3,
0x64, 0xf5,
0x86, 0x17,
0xa8, 0x39,
0xca, 0x5b,
0xec, 0x7d
};
MonkeyWrapWrap(D,cryptogram,tag,t_len,d8,0,header_3,112);
unsigned char d9[26]= {
0xd7, 0xf8, 0x78, 0x99, 0x19, 0x3a, 0xba, 0xdb,
0x5b, 0x7c, 0xfc, 0x1d, 0x9d, 0xbe, 0x3e, 0x5f,
0xdf, 0x00, 0x80, 0xa1, 0x21, 0x42, 0xc2, 0xe3,
0x63, 0x84
};
unsigned char header_4[14] = {
0x3a, 0xcb, 0x5c, 0xed,
0x7e, 0x0f, 0xa0, 0x31,
0xc2, 0x53, 0xe4, 0x75,
0x06, 0x97
};
MonkeyWrapWrap(D,cryptogram,tag,t_len,d9,208,header_4,112);

unsigned char header_5[24] = {
0x74, 0x05, 0x96, 0x27, 0xb8,
0x49, 0xda, 0x6b, 0xfc, 0x8d,
0x1e, 0xaf, 0x40, 0xd1, 0x62,
0xf3, 0xe3, 0x74, 0x05, 0x96,
0x27, 0xb8, 0x49, 0xda
};
MonkeyWrapWrap(D,cryptogram,tag,t_len,d9,0,header_5,192);
unsigned char d10[36] = {
0x35, 0x56, 0xd6, 0xf7, 0x77,
0x98, 0x18, 0x39, 0xb9, 0xda,
0x5a, 0x7b, 0xfb, 0x1c, 0x9c,
0xbd, 0x3d, 0x5e, 0xde, 0xff,
0x7f, 0xa0, 0x20, 0x41, 0xc1,
0xe2, 0x62, 0x83, 0x03, 0x24,
0xa4, 0xc5, 0x45, 0x66, 0xe6,
0x07
};
unsigned char header_6[24] = {
0x98, 0x29, 0xba, 0x4b, 0xdc, 0x6d, 0xfe, 0x8f, 0x20, 0xb1,
0x42, 0xd3, 0x64, 0xf5, 0x86, 0x17, 0x07, 0x98, 0x29, 0xba,
0x4b, 0xdc, 0x6d, 0xfe
};
MonkeyWrapWrap(D,cryptogram,tag,t_len,d10,288,header_6,192);
unsigned char header_7[38] = {
0x50, 0xe1, 0x72, 0x03, 0x94,
0x25, 0xb6, 0x47, 0xd8, 0x69,
0xfa, 0x8b, 0x1c, 0xad, 0x3e,
0xcf, 0xbf, 0x50, 0xe1, 0x72,
0x03, 0x94, 0x25, 0xb6, 0x47,
0xd8, 0x69, 0xfa, 0x8b, 0x1c,
0xad, 0x3e, 0x2e, 0xbf, 0x50,
0xe1, 0x72, 0x03
};
trace(printf("+\n+\n+\n+\n+\n+\n+\n+\n***************NOT WORKINGGGGGGG******************+\n+\n+\n+\n+\n+\n+\n+\n\n"));

MonkeyWrapWrap(D,cryptogram,tag,t_len,d10,0,header_7,304);
*/
	return;

/*unsigned char d10[26]= {
0xd7, 0xf8, 0x78, 0x99, 0x19, 0x3a, 0xba, 0xdb,
0x5b, 0x7c, 0xfc, 0x1d, 0x9d, 0xbe, 0x3e, 0x5f,
0xdf, 0x00, 0x80, 0xa1, 0x21, 0x42, 0xc2, 0xe3,
0x63, 0x84
};
unsigned char header_6[24] = {
0x98, 0x29, 0xba, 0x4b, 0xdc,
0x6d, 0xfe, 0x8f, 0x20, 0xb1,
0x42, 0xd3, 0x64, 0xf5, 0x86,
0x17, 0x07, 0x98, 0x29, 0xba,
0x4b, 0xdc, 0x6d, 0xfe
};*/

}

/*****************************************************************************
 * @brief: This set of functions prints the content of a generic state array
 * @author: Jacopo Bufalino - jacopobufalino@gmail.com
 * @date: 2016/27/11
 * @return: void
 * @arg: inpunt state array
 * @note: Use them just to debug the code
 *
 *****************************************************************************/

Duplex *DuplexInit(unsigned int f, unsigned int rho, unsigned int n_start,
		   unsigned int n_step, unsigned int n_stride)
{

	Duplex *D = calloc(1, sizeof(Duplex));
	D->f = f;
	D->rho = rho;
	D->n_start = n_start;
	D->n_step = n_step;
	D->n_stride = n_stride;

	return D;
}

/*****************************************************************************
 * @brief: This set of functions prints the content of a generic state array
 * @author: Jacopo Bufalino - jacopobufalino@gmail.com
 * @date: 2016/27/11
 * @return: void
 * @arg: inpunt state array
 * @note: Use them just to debug the code
 *
 *****************************************************************************/

void
MonkeyWrap(Duplex * D, unsigned char *cryptogram,
	   unsigned char *tag, unsigned int t_len,
	   unsigned char *key, unsigned int k_len,
	   unsigned char *nonce, unsigned int n_len,
	   unsigned char *data, unsigned long d_len,
	   unsigned char *header, unsigned long h_len)
{

	//trace(printf("Key = %s \nKeylen = %d\n",key,k_len));

	/* I have updated rho to get the desired value */
	D->r = D->rho + 4;

	trace(printf("MonkeyWrap\n"));
	//TODO: check if the value 8 is correct
	MonkeyWrapInitialize(D, key, k_len, nonce, n_len);
	MonkeyWrapWrap(D, cryptogram, tag, t_len, data, d_len, header, h_len);
	return;

}

/*****************************************************************************
 * @brief: This set of functions prints the content of a generic state array
 * @author: Jacopo Bufalino - jacopobufalino@gmail.com
 * @date: 2016/27/11
 * @return: void
 * @arg: inpunt state array
 * @note: Use them just to debug the code
 *
 *****************************************************************************/

void MonkeyWrapInitialize(Duplex * D, unsigned char *key, unsigned int k_len,
			  unsigned char *seq_no, unsigned int seq_len)
{

	unsigned char *result = NULL, *data_2_feed = NULL;
	unsigned long result_len;
	unsigned int i;
	trace(printf("MonkeyWrapInitialize\n"));
	trace(printf("Keylen is %u\n", k_len));
	trace(printf("NonceLen is %u\n", seq_len));
	/*Create keypack, than concatenate it with the public sequence number */
	keypack(&result, key, k_len, k_len + 16);
	result_len = k_len + 16;
	trace(printf("len after keypack is %u\n", k_len + 16));

	//TODO Make the error on the constant suppress.

	if (seq_len != 0) {
		unsigned int length;
		if (seq_len <= (D->f - k_len - 18))
			length = seq_len;
		else
			length = D->f - (k_len + 18);
		result_len =
		    concatenate(&data_2_feed, result, k_len + 16,
				seq_no, length);
		trace(printf("Resulting len of the nonce: %lu == %lu\n",
		       length, D->f - k_len - 18));

		for (i = 0; i < BYTE_LEN(result_len); i++)
			trace(printf("%.2X ", data_2_feed[i]));

		DuplexStart(D, data_2_feed, result_len);
	} else
		DuplexStart(D, result, result_len);
	return;

}

/*****************************************************************************
 * @brief: This set of functions prints the content of a generic state array
 * @author: Jacopo Bufalino - jacopobufalino@gmail.com
 * @date: 2016/27/11
 * @return: void
 * @arg: inpunt state array
 * @note: Use them just to debug the code
 *
 *****************************************************************************/

void MonkeyWrapWrap(Duplex * D, unsigned char *cryptogram,
		    unsigned char *tag, unsigned int t_len,
		    unsigned char *data, unsigned long d_len,
		    unsigned char *header, unsigned long h_len)
{

	/* Setup the number of blocks */
	unsigned long plain_blocks =
	    ((d_len / D->rho) + (d_len % D->rho ? 1 : 0)), header_blocks =
	    ((h_len / D->rho) + (h_len % D->rho ? 1 : 0)), data_size =
	    0, data_len = 0, last_block_size = 0, last_plain =
	    d_len % D->rho, last_header_len = h_len % D->rho, last_header = 0;
	uint64_t i = 0;
	unsigned char *data_concatenated = NULL, *Z = NULL, *crypto = NULL;
	unsigned char *data4second_step = NULL;
	unsigned int B0;

	if (header_blocks > 0)
		last_header = header_blocks - 1;

	/* TODO */
	/* allocate space for cryptogram */
	crypto = calloc(BYTE_LEN(d_len), sizeof(unsigned char));

	trace(printf("allocated %u bytes for crypto\n", BYTE_LEN(d_len)));
	trace(printf("****************MonkeyWrapWrap stats***********\n"));
	trace(printf("*\tThere are %lu blocks of text d_len/D->rho \n", plain_blocks));
	trace(printf("*\tData len d_len is  %lu\n", d_len));
	trace(printf("*\tD->rho is %u\n", D->rho));
	trace(printf("*\theader length is %u\n", h_len));
	trace(printf("*\theader blocks %u\n", header_blocks));

	trace(printf("***********************************************\n"));

	/*
	 * for i = 0 to ∥A∥ − 2 do
	 *      D.step(Ai||00, 0)
	 */
	unsigned int count = 0;
	for (i = 0; (i <= (header_blocks - 2)) && (header_blocks > 1); ++i)
	{
		count++;
		trace(printf("There are at least two headers! %d\n", i));
		data_size = concatenate_00(&data_concatenated,
					   &header[BYTE_LEN(D->rho) * i],
					   D->rho);
		DuplexStep(D, data_concatenated, D->rho + 2, 0);
		free(data_concatenated);
	}

	trace(printf("The loop A ... has been done %u times\n", count));
	/*End of first phase */
	trace(printf("\nMONKEYDUPLEX state after the \"for i=0 to ||A||-2\" loop:\n"));
	for (i = 0; i < (D->f / 8); ++i)
		trace(printf("%.2x ", D->state[i]));
	trace(printf("\n"));

	if (plain_blocks == 1)
		B0 = last_plain;
	else if (plain_blocks > 1)
		B0 = D->rho;
	else
		B0 = 0;
	trace(printf("B0 = %u\n", B0));
	trace(printf("last header = %u\n", last_header));
	data_len =
	    concatenate_01(&data4second_step,
			   &header[(last_header) * BYTE_LEN(D->rho)]
			   , last_header_len);

	trace(printf("data_len after concatenating_01 is: %u\n", data_len));
	trace(printf("data is %.2x\n", data4second_step[0]));
	for (i = 0; i < BYTE_LEN(data_len); i++)
		trace(printf("%.2x ", data4second_step[i]));
	trace(printf("\n"));
	/*      for (i = 0 ; i< BYTE_LEN(data_len) ; i++)
	   trace(printf("%.2x ",header[i]));
	   trace(printf("\n")); */
	Z = DuplexStep(D, data4second_step, data_len, B0);
	free(data4second_step);

	if (!Z)
		trace(printf("Z is not allocated\n"));
	trace(printf("\n---C0---\n"));
	for (i = 0; i < BYTE_LEN(B0); i++) {
		crypto[i] = data[i] ^ Z[i];
		//trace(printf("%.2x ",crypto[i]));

	}

	free(Z);

	// at the end it will be equal to Z...
	trace(printf("\nMONKEYDUPLEX state after stepping the last block of A:\n"));
	for (i = 0; i < (D->f / 8); ++i)
		trace(printf("%.2x ", D->state[i]));
	trace(printf("\n"));

	unsigned char *temp_i = NULL;

	/* computing Ci+i */
	for (i = 0; (i <= plain_blocks - 2) && (plain_blocks > 1); i++) {
		trace(printf("COMPUTING Ci+1\n"));
		concatenate_11(&temp_i, &data[i * BYTE_LEN(D->rho)], D->rho);

		Z = DuplexStep(D, temp_i, D->rho + 2, D->rho);
		for (unsigned int j = 0;
		     j < (i ==
			  (plain_blocks -
			   2) ? BYTE_LEN(last_header_len) : BYTE_LEN(D->rho));
		     j++)
			crypto[BYTE_LEN(D->rho) * (i + 1) + j] =
			    data[BYTE_LEN(D->rho) * (i + 1) + j] ^ Z[j];
		/*trace(printf("TODO: implement Ci\n"));
		   for ( int j = 0 ; j < BYTE_LEN(D->rho) ; ++j)
		   trace(printf("%.2x ",temp_i[j]));
		   trace(printf("\n")); */
		free(temp_i);

	}
	trace(printf("\nMONKEYDUPLEX statiie after for B......:\n"));
	for (i = 0; i < (D->f / 8); ++i)
		trace(printf("%.2x ", D->state[i]));
	trace(printf("\n"));

	//data_len = concatenate_10(&data4second_step,data, last_block_size);
	// free(data4second_step);
//EDIT :
	unsigned char dummy = 0x10;
	unsigned char *temp_tag;
	unsigned int temp_tag_len = D->rho;
	unsigned char *ttag;
	unsigned long ttag_len;
	unsigned char *in_put;
	concatenate_10(&in_put, &data[(plain_blocks - 1) * BYTE_LEN(D->rho)],
		       last_plain);
/*trace(printf("++++++++++++++++++++++++++\n"));
for ( i = 0 ; i < BYTE_LEN(last_plain+2) ; ++i)
		trace(printf("%.2x ",in_put[i]));
	trace(printf("\n++++++++++++++++++++++++\n"));*/
	temp_tag = DuplexStride(D, in_put, last_plain + 2, D->rho);
	free(in_put);
	trace(printf("\nMONKEYDUPLEX statiie after stepping the last block of B:\n"));
	for (i = 0; i < (D->f / 8); ++i)
		trace(printf("%.2x ", D->state[i]));
	trace(printf("\n"));
	unsigned char *tmp;
	while (temp_tag_len < 128) {
		trace(printf("ANOMAL CASE ************************* \n ABORT"));
		//exit(1);
		concatenate(&tmp, temp_tag, D->rho,
			    DuplexStep(D, NULL, 0, D->rho), D->rho);
		free(temp_tag);
	}
	trace(printf("\n\n+++++++++TAG+++++++++++\n\n"));
	for (int i = 0; i < BYTE_LEN(128); i++)
		trace(printf("%.2X ", temp_tag[i]));
	trace(printf("\n"));
	trace(printf("\n\n+++++++++CRYPTO+++++++++++\n\n"));
	for (int i = 0; i < BYTE_LEN(d_len); i++)
		trace(printf("%.2X ", crypto[i]));
	trace(printf("\n"));

	if (temp_tag) {

		memcpy(tag, temp_tag, BYTE_LEN(t_len) * sizeof(char));

		free(temp_tag);
	}

	if (cryptogram) {

		memcpy(cryptogram, crypto, BYTE_LEN(d_len) * sizeof(char));
		free(crypto);
	}

}

/*****************************************************************************
 * @brief: This set of functions prints the content of a generic state array
 * @author: Jacopo Bufalino - jacopobufalino@gmail.com
 * @date: 2016/27/11
 * @return: void
 * @arg: inpunt state array
 * @note: Use them just to debug the code
 *
 *****************************************************************************/

void DuplexStart(Duplex * D, unsigned char *I, unsigned long i_len)
{
	trace(printf("Inside DuplexStart\n"));
	unsigned char *padding = NULL, *state = NULL;
	unsigned long pad_len;
	/* Add padding */
	trace(printf("D->f:%u, I_len:%u\n", D->f, i_len));
	if (i_len % D->f) {
		pad_len = pad10x1(&padding, D->f, i_len);
		trace(printf("After padding\n"));
		unsigned long result =
		    concatenate(&state, I, i_len, padding, pad_len);
		trace(printf("After concatenate, the length is: %lu\n", result));
		trace(printf("STATE BEFORE KECCAK_P_STAR\n"));
		//TODO put 200 in a more elegant form
		for (unsigned int i = 0; i < 200; i++)
			trace(printf("%.2x ", state[i]));
		trace(printf("\n"));
	} else {
		trace(printf("no pad needed\n"));
		state = I;
	}
	trace(printf("n_start is %u\n", D->n_start));

	/*
	   for (int i = 0 ; i < 200 ; i++)
	   trace(printf("%.2x ",state[i]));
	   trace(printf("\n\n"));
	 */
	D->state = keccak_p_star(state, D->rho, D->n_start, D->f);
	free(padding);
	free(state);
	for (int i = 0; i < 200; i++)
		trace(printf("%.2x ", D->state[i]));
	trace(printf("\n\n"));

}

/*****************************************************************************
 * @brief: This set of functions prints the content of a generic state array
 * @author: Jacopo Bufalino - jacopobufalino@gmail.com
 * @date: 2016/27/11
 * @return: void
 * @arg: inpunt state array
 * @note: Use them just to debug the code
 *
 *****************************************************************************/

unsigned char *DuplexStep(Duplex * D, unsigned char *sigma, unsigned long s_len,
			  unsigned long l)
{

	unsigned char *pad = NULL, *P = NULL;
	unsigned long pad_len, P_len, Pc_len;
	/* concatenate padding to the input string sigma */
	pad_len = pad10x1(&pad, D->r, s_len);
	P_len = concatenate(&P, sigma, s_len, pad, pad_len);

	/*for (unsigned int i = 0 ; i < P_len/8 +1 ; i++)
	   trace(printf("%.2x ",P[i]));
	   trace(printf("\n")); */

	/* xor the current state with the new string  */
	for (uint8_t i = 0; i < BYTE_LEN(P_len); ++i)
		D->state[i] = D->state[i] ^ P[i];
/*
trace(printf("After the xor\n"));
	for (unsigned int i = 0 ; i < 200 ; i++)
		trace(printf("%.2x ",D->state[i]));
	trace(printf("\n"));*/

	trace(printf("****************DuplexStep stats***********\n"));
	trace(printf("*\tSigma len is %lu bits\n", s_len));
	trace(printf("*\tThe value of l is %lu\n", l));
	trace(printf("*\tPadding len is %lu\n", pad_len));
	trace(printf("*\tP string len is %lu\n", P_len));
	trace(printf("*\tb-r is %lu\n", D->f - D->r));
	trace(printf("****************************************\n"));

	/* apply keccak_p_star function */
	unsigned char *state = keccak_p_star(D->state, D->rho,
					     D->n_step, D->f);

	/* copy the output of keccak to the current state */
	free(D->state);
	D->state = state;
	/* duplicate the state array and truncate it up to l bits */
	unsigned char *ret_val = calloc(BYTE_LEN(l), sizeof(char));
	memcpy(ret_val, state, BYTE_LEN(l) * sizeof(char));
	/* free the memory */
	free(pad);
	free(P);

	return ret_val;

}

/*****************************************************************************
 * @brief: This set of functions prints the content of a generic state array
 * @author: Jacopo Bufalino - jacopobufalino@gmail.com
 * @date: 2016/27/11
 * @return: void
 * @arg: inpunt state array
 * @note: Use them just to debug the code
 *
 *****************************************************************************/

unsigned char *DuplexStride(Duplex * D, unsigned char *sigma,
			    unsigned long s_len, unsigned long l)
{

	unsigned char *pad = NULL, *P = NULL;
	unsigned long pad_len, P_len, Pc_len;
	/* concatenate padding to the input string sigma */
	pad_len = pad10x1(&pad, D->r, s_len);
	P_len = concatenate(&P, sigma, s_len, pad, pad_len);

	/*for (unsigned int i = 0 ; i < P_len/8 +1 ; i++)
	   trace(printf("%.2x ",P[i]));
	   trace(printf("\n")); */

	/* xor the current state with the new string  */
	for (uint8_t i = 0; i < BYTE_LEN(P_len); ++i)
		D->state[i] = D->state[i] ^ P[i];
/*
trace(printf("After the xor\n"));
	for (unsigned int i = 0 ; i < 200 ; i++)
		trace(printf("%.2x ",D->state[i]));
	trace(printf("\n"));*/

	trace(printf("****************DuplexStride stats***********\n"));
	trace(printf("*\tSigma len is %lu bits\n", s_len));
	trace(printf("*\tThe value of l is %lu\n", l));
	trace(printf("*\tPadding len is %lu\n", pad_len));
	trace(printf("*\tP string len is %lu\n", P_len));
	trace(printf("*\tb-r is %lu\n", D->f - D->r));
	trace(printf("****************************************\n"));

	/* apply keccak_p_star function */
	unsigned char *state = keccak_p_star(D->state, D->rho,
					     D->n_stride, D->f);

	/* copy the output of keccak to the current state */
	free(D->state);
	D->state = state;
	/* duplicate the state array and truncate it up to l bits */
	unsigned char *ret_val = calloc(BYTE_LEN(l), sizeof(char));
	memcpy(ret_val, state, BYTE_LEN(l) * sizeof(char));
	/* free the memory */
	free(pad);
	free(P);

	return ret_val;
}

/*****************************************************************************
 * @brief: This function implements the Keypack algorithm (see sec. 1.4)
 * @author: Jacopo Bufalino - jacopobufalino@gmail.com
 * @date: 2016/27/11
 * @return: void
 * @arg: Key - keysize - alignment value
 *
 *****************************************************************************/
void
keypack(unsigned char **result, const unsigned char *key, unsigned long n_bits,
	unsigned long l)
{
	//if ( n_bits > (255*8) || n_bits%8 ) exit(EXIT_FAILURE);

	unsigned char *res = NULL, *simple_pad = NULL, *pad_key = NULL;
	unsigned long result_size, l_conc;
	uint8_t B_val = l / 8, padding = 0x01;
	/* concatenate enc(l/8) with the key */
	result_size = concatenate(&pad_key, &B_val, 8, key, n_bits);
	if (result_size <= 0)
		exit(EXIT_FAILURE);
	/* concatenate 0x01 to the previous string */
	result_size = concatenate(&res, pad_key, n_bits + 8, &padding, 8);
	/* create an empty array of the desired size l-result_size
	 * and concatenate it to the previous one to get the final
	 * result */
	simple_pad = calloc(BYTE_LEN(l - result_size), sizeof(unsigned char));

	l_conc =
	    concatenate(result, res, result_size, simple_pad, l - result_size);
	trace(printf("Len of the array after keypack is: %lu\n", l_conc));
	trace(printf("****************Keypack stats***********\n"));
	trace(printf("*\tKeylen is %lu bits\n", n_bits));
	trace(printf("*\tKeylen is %u bytes\n", BYTE_LEN(n_bits)));
	trace(printf("*\tThe first byte of the new array should be %.2X\n", B_val));
	trace(printf("****************************************\n"));
	free(res);
	free(pad_key);
	free(simple_pad);
	return;
}
