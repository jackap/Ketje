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
	printf("Inside ketje\n");
	Duplex *D = DuplexInit(1600,256,12,1,6);
	if (key == NULL) return;
	//printf("Key = %s \nKeylen = %d\n",key,k_len); 
	MonkeyWrap(D,cryptogram,tag, t_len,key,
			k_len,nonce,n_len,data, d_len,header, h_len);


	//printf("Size of the algorithm is %u\n",D->n_stride);
	/* Implement this function */

	return;
}

Duplex*
DuplexInit(unsigned int f,unsigned int rho,unsigned int n_start,
		unsigned int n_step,unsigned int n_stride){

	Duplex *D = calloc(1,sizeof(Duplex));
	D->f = f;
	D->rho = rho;
	D->n_start = n_start;
	D->n_step = n_step;
	D->n_stride = n_stride;

	return D;
}



	void
MonkeyWrap(Duplex *D, unsigned char *cryptogram,
		unsigned char *tag, unsigned int t_len,
		unsigned char *key, unsigned int k_len,
		unsigned char *nonce, unsigned int n_len,
		unsigned char *data, unsigned long d_len,
		unsigned char *header, unsigned long h_len)
{

	//printf("Key = %s \nKeylen = %d\n",key,k_len); 


	printf("MonkeyWrap\n");
	//TODO: check if the value 8 is correct
	MonkeyWrapInitialize(D,key,k_len,nonce,n_len);
	return;

}

void MonkeyWrapInitialize(Duplex *D, unsigned char *key, unsigned int k_len,
		unsigned char* seq_no,unsigned int seq_len){
	unsigned char *result=NULL,*data_2_feed=NULL;
	unsigned long result_len;
	unsigned int i;
	printf("MonkeyWrapInitialize\n");
	printf("Keylen is %u\n",k_len);
	/*Create keypack, than concatenate it with the public sequence number */
	keypack(&result,key,k_len,k_len+16);
	result_len = k_len+16;
	printf("len after keypack is %u\n",k_len+16);

	//TODO Make the error on the constant suppress.

	if (seq_len != 0){
		result_len = concatenate(&data_2_feed,result,k_len+16,
				&seq_no,seq_len); 
		printf("Resulting len before Duplex Start: %lu\n",result_len);


		DuplexStart(D,data_2_feed,result_len);}
	else 
		DuplexStart(D,result,result_len);
	/*
	   for (i = 0 ; i < 200 ; i++)
	   printf("%.2x ",D->state[i]);
	   */
	return;


}

void 
DuplexStart(Duplex *D,unsigned char *I,unsigned long i_len){
	printf("Inside DuplexStart\n");
	unsigned char *padding=NULL,*state=NULL;
	unsigned long pad_len;
	/* Add padding */
	printf("D->f:%u, I_len:%u\n",D->f, i_len);
	if (i_len%D->f){
		pad_len = pad10x1(&padding,D->f,i_len);
		printf("After padding\n");
		concatenate(&state,I,i_len,padding,pad_len);
		printf("After concatenate\n");
		//TODO put 200 in a more elegant form
		for (unsigned int i = 0 ; i < 200 ; i++)
			printf("%.2x ",state[i]);
		printf("\n");
	}
	else {
		printf("no pad needed\n");
		state = I;
	}
	printf("n_start is %u\n",D->n_start);

	/*
	   for (int i = 0 ; i < 200 ; i++)
	   printf("%.2x ",state[i]);
	   printf("\n\n");
	   */
	D->state = keccak_p_star(state,D->rho,D->n_start,D->f);
	free(padding);
	free(state);
}










void
keypack(unsigned char** result,const unsigned char *key,unsigned long n_bits,
		unsigned long l){
	if ( n_bits > (255*8) || n_bits%8 ) exit(EXIT_FAILURE);
	/*
	   printf("Keypack is here\n");
	   printf("K = %u - l = %u\n",n_bits,l);
	   */
	int i;
	unsigned char*res = NULL;
	unsigned char *pad_key=NULL;
	unsigned long result_size;
	uint8_t B_val = l/8, padding=0x01;
printf("****************Keypack stats***********\n");
printf("*\tKeylen is %u bits\n",n_bits);
printf("*\tKeylen is %u bytes\n",B_val);
printf("*\tThe value of l is %lu\n",l);
printf("****************************************\n");
	// you cannot have  %8 != 0
	//printf("Concatenating key with its value in bytes\n");
	result_size = concatenate(&pad_key,&B_val, 8 ,key, n_bits);
	/*
	   for (i = 0 ; i < (result_size)/8 ; i++)
	   printf("%.2x ",pad_key[i]);
	   printf("\n");
	   */
	//printf("The first byte of the array is %.2x\n",pad_key[0]);
	if (result_size <= 0 ) exit(EXIT_FAILURE);
	//alignment value is l but I have already key + n_BYTES
	if (result_size <= 0 ) exit(EXIT_FAILURE);
	result_size = concatenate(result,pad_key,n_bits +8, &padding,8);
	//printf("At the end result_size is %u\n",result_size);
	//now keypack should be completed.A
	//printf("OK\n");
	free(pad_key);
	return;
}


























