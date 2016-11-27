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
	/*Initialize the specific parameters */
	Duplex *D = DuplexInit(1600, 256, 12, 1, 6);

	/*Call the MonkeyWrap function to encrypt data */
	MonkeyWrap(D, cryptogram, tag, t_len, key,
			k_len, nonce, n_len, data, d_len, header, h_len);
	return;


}



/*****************************************************************************
 * @brief: This function builds the MONKEYWRAP encryption mode (Algorithm 2).
 * @author: Jacopo Bufalino - jacopobufalino@gmail.com
 * @date: 2016/27/11
 * @return: void
 * @arg: Duplex object plus all the arguments passed to the ketje function.
 *
 *****************************************************************************/

	void
MonkeyWrap(Duplex * D, unsigned char *cryptogram,
		unsigned char *tag, unsigned int t_len,
		const unsigned char *key, unsigned int k_len,
		const unsigned char *nonce, unsigned int n_len,
		const unsigned char *data, unsigned long d_len,
		const unsigned char *header, unsigned long h_len)
{

	//trace(printf("Key = %s \nKeylen = %d\n",key,k_len));

	trace(printf("MonkeyWrap\n"));
	MonkeyWrapInitialize(D, key, k_len, nonce, n_len);
	MonkeyWrapWrap(D, cryptogram, tag, t_len, data, d_len, header, h_len);
	return;

}

/*****************************************************************************
 * @brief: Implementation of the W.Initialize interface
 * @author: Jacopo Bufalino - jacopobufalino@gmail.com
 * @date: 2016/27/11
 * @return: void
 * @arg: Duplex object,key and nonce.
 *
 *****************************************************************************/

	void
MonkeyWrapInitialize(Duplex * D, const unsigned char *key, unsigned int k_len,
		const unsigned char *seq_no, unsigned int seq_len)
{

	unsigned char *result = NULL, *data_2_feed = NULL;
	unsigned long result_len;

	trace(printf("MonkeyWrapInitialize\n"));
	trace(printf("Keylen is %u\n", k_len));
	trace(printf("NonceLen is %u\n", seq_len));

	/*Create keypack, than concatenate it with the public sequence number */
	keypack(&result, key, k_len, k_len + 16);
	result_len = k_len + 16;
	trace(printf("len after keypack is %u\n", k_len + 16));


	/* Check if nonce is not NULL */
	if (seq_len != 0) {
		unsigned int length;
		/* cut nonce if it is too big */
		if (seq_len <= (D->f - k_len - 18))
			length = seq_len;
		else
			length = D->f - (k_len + 18);

		result_len =
			concatenate(&data_2_feed, result, k_len + 16,
					seq_no, length);

		trace(printf("Resulting len of the nonce: %lu == %lu\n",
					(unsigned long)length,
					(unsigned long) D->f - k_len - 18));

		/*for (unsigned int i = 0; i < BYTE_LEN(result_len); i++)
		  trace(printf("%.2X ", data_2_feed[i]));*/

		DuplexStart(D, data_2_feed, result_len);
	} else
		DuplexStart(D, result, result_len);
	return;

}

/*****************************************************************************
 * @brief: Implementation of MONKEYWRAP.WRAP, the generic encryption function
 * @author: Jacopo Bufalino - jacopobufalino@gmail.com
 * @date: 2016/27/11
 * @return: cryptogram and tag
 * @arg: DUPLEX Object, header,data
 *
 *****************************************************************************/

void MonkeyWrapWrap(Duplex * D, unsigned char *cryptogram,
		unsigned char *tag, unsigned int t_len,

		const unsigned char *data, unsigned long d_len,
		const unsigned char *header, unsigned long h_len)
{

	/* Setup the number of blocks */
	unsigned long plain_blocks =
		((d_len / D->rho) + (d_len % D->rho ? 1 : 0)), header_blocks =
		((h_len / D->rho) + (h_len % D->rho ? 1 : 0)), data_size =
		0, data_len = 0,  last_plain =
		d_len % D->rho, last_header_len = h_len % D->rho,
	last_header = 0;
	uint64_t i = 0;
	unsigned char *data_concatenated = NULL, *Z = NULL, *crypto = NULL;
	unsigned char *data4second_step = NULL;
	unsigned int B0;

	/* Find the size of the first block of B and the last of A */
	if (header_blocks > 0)
		last_header = header_blocks - 1;

	if (plain_blocks == 1)
		B0 = last_plain;
	else if (plain_blocks > 1)
		B0 = D->rho;
	else
		B0 = 0;

	/* allocate space for cryptogram */
	crypto = calloc(BYTE_LEN(d_len), sizeof(unsigned char));
	/*
	   trace(printf("allocated %u bytes for crypto\n", BYTE_LEN(d_len)));
	   trace(printf("****************MonkeyWrapWrap stats***********\n"));
	   trace(printf("*\tThere are %lu blocks of text d_len/D->rho \n",
	   plain_blocks));
	   trace(printf("*\tData len d_len is  %lu\n", d_len));
	   trace(printf("*\tD->rho is %u\n", D->rho));
	   trace(printf("*\theader length is %u\n", h_len));
	   trace(printf("*\theader blocks %u\n", header_blocks));
	   trace(printf("***********************************************\n"));
	   */

	/*
	 * for i = 0 to ∥A∥ − 2 do
	 *      D.step(Ai||00, 0)
	 */
	for (i = 0; (i <= (header_blocks - 2)) && (header_blocks > 1); ++i)
	{
		data_size = concatenate_00(&data_concatenated,
				&header[BYTE_LEN(D->rho) * i],
				D->rho);
		DuplexStep(D, data_concatenated, data_size, 0);
		free(data_concatenated);
	}

	/*End of first phase */
	/*trace(
	  printf(
	  "\nMONKEYDUPLEX state after the \"for i=0 to ||A||-2\" loop:\n"));
	  for (i = 0; i < (D->f / 8); ++i)
	  trace(printf("%.2x ", D->state[i]));
	  trace(printf("\n"));
	  */

	data_len =
		concatenate_01(&data4second_step,
				&header[(last_header) * BYTE_LEN(D->rho)]
				, last_header_len);

	trace(printf("data_len after concatenating_01 is: %lu\n", data_len));
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
	trace(printf(
		"\nMONKEYDUPLEX state after stepping the last block of A:\n"));
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
				j < (i ==(plain_blocks -2) ?	
				BYTE_LEN(last_header_len) : BYTE_LEN(D->rho));
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
	unsigned char *temp_tag;
	unsigned int temp_tag_len = D->rho;

	unsigned char *in_put;
	concatenate_10(&in_put, &data[(plain_blocks - 1) * BYTE_LEN(D->rho)],
			last_plain);
	/*trace(printf("++++++++++++++++++++++++++\n"));
	  for ( i = 0 ; i < BYTE_LEN(last_plain+2) ; ++i)
	  trace(printf("%.2x ",in_put[i]));
	  trace(printf("\n++++++++++++++++++++++++\n"));*/
	temp_tag = DuplexStride(D, in_put, last_plain + 2, D->rho);
	free(in_put);
	trace(printf(
		"\nMONKEYDUPLEX state after stepping the last block of B:\n"));
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
	for ( i = 0; i < BYTE_LEN(128); i++)
		trace(printf("%.2X ", temp_tag[i]));
	trace(printf("\n"));
	trace(printf("\n\n+++++++++CRYPTO+++++++++++\n\n"));
	for ( i = 0; i < BYTE_LEN(d_len); i++)
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
 * @brief: Through this function it is possible to create a Duplex instance
 * @author: Jacopo Bufalino - jacopobufalino@gmail.com
 * @date: 2016/27/11
 * @return: Duplex struct
 * @note: the field f represent the size of the keccak function (usually b).
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
	D->r = D->rho + 4;
	D->state = NULL;

	return D;
}

/*****************************************************************************
 * @brief: Implements DUPLEX.START interface.
 * @author: Jacopo Bufalino - jacopobufalino@gmail.com
 * @date: 2016/27/11
 * @return: void
 * @arg: Duplex Object initial seed and length.
 *
 *****************************************************************************/

void DuplexStart(Duplex * D, unsigned char *I, unsigned long i_len)
{
	trace(printf("Inside DuplexStart\n"));
	unsigned char *padding = NULL, *state = NULL;
	unsigned long pad_len;
	/* Add padding */
	trace(printf("D->f:%u, I_len:%lu\n", D->f, i_len));
	if (i_len % D->f) {
		pad_len = pad10x1(&padding, D->f, i_len);
		trace(printf("After padding\n"));
		concatenate(&state, I, i_len, padding, pad_len);
	} else {
		trace(printf("no pad needed\n"));
		state = I;
	}

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
 * @brief: The following two functions implement the interfaces DUPLEX.STEP
 * and DUPLEX.STRIDE. The code is more or less the same but I prefered not to
 * create a wrapper.
 * @author: Jacopo Bufalino - jacopobufalino@gmail.com
 * @date: 2016/27/11
 * @return: unsigned char *
 * @arg: Duplex Object, sigma and length of the return array
 *
 *****************************************************************************/

	unsigned char *
DuplexStep(Duplex * D, unsigned char *sigma, unsigned long s_len,
		unsigned long l)
{

	unsigned char *pad = NULL, *P = NULL;
	unsigned long pad_len, P_len ;
	/* concatenate padding to the input string sigma */
	pad_len = pad10x1(&pad, D->r, s_len);
	P_len = concatenate(&P, sigma, s_len, pad, pad_len);

	/* xor the current state with the new string  */
	for (uint8_t i = 0; i < BYTE_LEN(P_len); ++i)
		D->state[i] = D->state[i] ^ P[i];

	trace(printf("****************DuplexStep stats***********\n"));
	trace(printf("*\tSigma len is %lu bits\n", s_len));
	trace(printf("*\tThe value of l is %lu\n", l));
	trace(printf("*\tPadding len is %lu\n", pad_len));
	trace(printf("*\tP string len is %lu\n", P_len));
	trace(printf("*\tb-r is %u\n", D->f - D->r));
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

	unsigned char *
DuplexStride(Duplex * D, unsigned char *sigma,
		unsigned long s_len, unsigned long l)
{

	unsigned char *pad = NULL, *P = NULL;
	unsigned long pad_len, P_len;
	/* concatenate padding to the input string sigma */
	pad_len = pad10x1(&pad, D->r, s_len);
	P_len = concatenate(&P, sigma, s_len, pad, pad_len);

	/* xor the current state with the new string  */
	for (uint8_t i = 0; i < BYTE_LEN(P_len); ++i)
		D->state[i] = D->state[i] ^ P[i];

	trace(printf("****************DuplexStride stats***********\n"));
	trace(printf("*\tSigma len is %lu bits\n", s_len));
	trace(printf("*\tThe value of l is %lu\n", l));
	trace(printf("*\tPadding len is %lu\n", pad_len));
	trace(printf("*\tP string len is %lu\n", P_len));
	trace(printf("*\tb-r is %u\n", D->f - D->r));
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
		concatenate(result, res, result_size,
				simple_pad, l - result_size);

	trace(printf("Len of the array after keypack is: %lu\n", l_conc));
	trace(printf("****************Keypack stats***********\n"));
	trace(printf("*\tKeylen is %lu bits\n", n_bits));
	trace(printf("*\tKeylen is %lu bytes\n", BYTE_LEN(n_bits)));
	trace(printf("*\tThe first byte of the new array should be %.2X\n",
				B_val));
	trace(printf("****************************************\n"));

	free(res);
	free(pad_key);
	free(simple_pad);
	return;
}
