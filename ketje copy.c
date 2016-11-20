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
	/*Initialize the specific parameters*/
	Duplex *D = DuplexInit(1600,256,12,1,6);
	if (key == NULL) return;
	/*Call the MonkeyWrap function to encrypt data*/
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

	/* I have updated rho to get the desired value */
	D->r = D->rho + 4;

	printf("MonkeyWrap\n");
	//TODO: check if the value 8 is correct
	MonkeyWrapInitialize(D,key,k_len,nonce,n_len);
	MonkeyWrapWrap(D,cryptogram,tag,t_len,data,d_len,header,h_len);
	return;

}

void MonkeyWrapInitialize(Duplex *D, unsigned char *key, unsigned int k_len,
		unsigned char* seq_no,unsigned int seq_len){
	
	unsigned char *result=NULL,*data_2_feed=NULL;
	unsigned long result_len;
	unsigned int i;
	printf("********MonkeyWrapInitialize********\n");
	printf("Keylen is %u\n",k_len);
	printf("NonceLen is %u\n",seq_len);
	/*Create keypack, than concatenate it with the public sequence number */
	keypack(&result,key,k_len,k_len+16);
	result_len = k_len+16;
	printf("len after keypack is %u\n",k_len+16);
	printf("*************************************\n");
	for (i = 0 ; i < BYTE_LEN(k_len+16) ; i++)
		printf("%.2X ",result[i]);
	printf("\n");

	//TODO Make the error on the constant suppress.

	if (seq_len != 0){

		result_len = concatenate(&data_2_feed,result,result_len,
				seq_no,seq_len); 
		
		printf("Resulting len before Duplex Start: %lu\n",result_len);
		printf("State after concatenate");
		for (i = 0 ; i < BYTE_LEN(result_len) ; i++)
		printf("%.2X ",data_2_feed[i]);
		printf("\n");
		
		DuplexStart(D,data_2_feed,result_len);
		//free(data_2_feed);
	}
	else 
		DuplexStart(D,result,result_len);
	//free(result);

	return;


}

void MonkeyWrapWrap(Duplex *D,unsigned char *cryptogram, 
		unsigned char *tag, unsigned int t_len,
		unsigned char *data, unsigned long d_len,
		unsigned char *header, unsigned long h_len){

	/* Setup the number of blocks */
	unsigned long plain_blocks = d_len/D->rho, 
	header_blocks = h_len/D->rho;
	uint8_t i = 0;
	unsigned char* data_concatenated;
	unsigned long data_size;
	unsigned long last_block_size =  0 ; // famo finta che è zero
	printf("****************MonkeyWrapWrap stats***********\n");
	printf("*\tThere are %lu blocks of text d_len/D->rho \n",plain_blocks);
	printf("*\tData len d_len is  %lu\n",d_len);
	printf("*\tD->rho is %u\n",D->rho);

	printf("***********************************************\n");

	if (plain_blocks > 0 )
		for ( i = 0 ; i < (plain_blocks -2)  ; ++i){

			data_size = concatenate_00(&data_concatenated,
			&data[i],D->rho+2);
			DuplexStep(D,data[i],D->r,0);
			free(data_concatenated);

		}

	/*End of first phase */

	printf("\nMONKEYDUPLEX state after the \"for i=0 to ||A||-2\" loop:\n");
	for ( i = 0 ; i < (D->f/8) ; ++i)
		printf("%.2x ",D->state[i]);
	printf("\n");


/*
* TODO I am omitting the cont.d of the algorithm because it is always null
NB: cryptogram is already allocated
*/

	// Using some shortcuts to go straight to the point 

	unsigned char * data4second_step = NULL;
	unsigned int data_len;

	data_len = concatenate_01(&data4second_step,data, last_block_size);
	printf("data_len after concatenate is: %u\n",data_len);
	printf("data is %.2x\n",data4second_step[0]);
	//header is zero, and the total length is 2! 
	DuplexStep(D,data4second_step,data_len,0);
	// at the end it will be equal to Z...
	printf("\nMONKEYDUPLEX statiie after stepping the last block of A:\n");
	for ( i = 0 ; i < (D->f/8) ; ++i)
		printf("%.2x ",D->state[i]);
	printf("\n");


	header_blocks = h_len/D->rho;
	if (header_blocks > 0 ) 
	for (i = 0 ; i < header_blocks - 2 ; i++)
	{
		
	
		printf("TODO: implement Ci\n");
	
	
	
	}

free(data4second_step);
	data_len = concatenate_10(&data4second_step,data, last_block_size);

//EDIT :
unsigned char dummy = 0x10;
unsigned char *temp_tag;
unsigned int temp_tag_len = D->f;
unsigned char *ttag;
unsigned long ttag_len;
temp_tag = DuplexStride(D,data4second_step,data_len,D->rho);
	printf("\nMONKEYDUPLEX statiie after stepping the last block of B:\n");
	for ( i = 0 ; i < (D->f/8) ; ++i)
		printf("%.2x ",D->state[i]);
	printf("\n");
/*
while (temp_tag_len < t_len){
DuplexStep(D,NULL,0,D->rho);
	



}
*/



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
	 keccak_p_star(I,D->rho,D->n_start,D->f);
	printf("dfsdfdsfsdfsfsdf");
	//free(padding);
	//free(state);
	printf("After freeeee");return;
}

unsigned char*
DuplexStep(Duplex *D, unsigned char *sigma,unsigned long s_len,
		unsigned long l){

	/* rho must be less than l and sigma len */
	if (l > D->rho || s_len > D->rho) exit(EXIT_FAILURE);
	unsigned char *pad,*P,*Pc;
	unsigned long pad_len,P_len,Pc_len;

	pad_len = pad10x1(&pad, D->r,s_len);
	P_len = concatenate(&P,sigma,s_len,pad,pad_len);

	for (unsigned int i = 0 ; i < P_len/8 +1 ; i++)
		printf("%.2x ",P[i]);
	printf("\n");


	/* Now I have to concatenate b-r zeros */
	//Pc = calloc((P_len+(D->f - D->r))/8,sizeof(unsigned char));
	//memcpy(Pc,&P,P_len/8);
	/* It could also be unuseful ... TODO check*/
	for (uint8_t i = 0 ; i < BYTE_LEN(P_len)  ; ++i ) {
		D->state[i] = D->state[i] ^ P[i];


	}
printf("After the xor\n");
	for (unsigned int i = 0 ; i < 200 ; i++)
		printf("%.2x ",D->state[i]);
	printf("\n");



	printf("****************DuplexStep stats***********\n");
	printf("*\tSigma len is %lu bits\n",s_len);
	printf("*\tThe value of l is %lu\n",l);
	printf("*\tPadding len is %lu\n",pad_len);
	printf("*\tP string len is %lu\n",P_len);
	printf("*\tb-r is %lu\n",D->f- D->r);

	printf("****************************************\n");

	unsigned char * state = keccak_p_star(D->state,D->rho,D->n_step,D->f);
	//free(D->state);
	//free(pad);
	//free(P);
	//free(Pc);

	D->state = state;



}

unsigned char*
DuplexStride(Duplex *D, unsigned char *sigma,unsigned long s_len,
		unsigned long l){

	/* rho must be less than l and sigma len */
	if (l > D->rho || s_len > D->rho) exit(EXIT_FAILURE);
	unsigned char *pad,*P,*Pc;
	unsigned long pad_len,P_len,Pc_len;

	pad_len = pad10x1(&pad, D->r,s_len);
	P_len = concatenate(&P,sigma,s_len,pad,pad_len);

	for (unsigned int i = 0 ; i < P_len/8 +1 ; i++)
		printf("%.2x ",P[i]);
	printf("\n");


	/* Now I have to concatenate b-r zeros */
	//Pc = calloc((P_len+(D->f - D->r))/8,sizeof(unsigned char));
	//memcpy(Pc,&P,P_len/8);
	/* It could also be unuseful ... TODO check*/
	for (uint8_t i = 0 ; i < BYTE_LEN(P_len)  ; ++i ) {
	D->state[i] = D->state[i] ^ P[i];
//	printf("%.2x ^  %.2x = %.2x\n", D->state[i], P[i],D->state[i] ^ P[i]);
	}
printf("After the xor\n");
	for (unsigned int i = 0 ; i < 200 ; i++)
		printf("%.2x ",D->state[i]);
	printf("\n");



	printf("****************DuplexStride stats***********\n");
	printf("*\tSigma len is %lu bits\n",s_len);
	printf("*\tThe value of l is %lu\n",l);
	printf("*\tPadding len is %lu\n",pad_len);
	printf("*\tP string len is %lu\n",P_len);
	printf("*\tb-r is %lu\n",D->f- D->r);

	printf("****************************************\n");

	unsigned char * state = keccak_p_star(D->state,D->rho,
			D->n_stride,D->f);

	printf("After keccak\n");
	
	free(D->state);
	
	
	
	free(pad);
	free(P);
	free(Pc);

	D->state = state;

	unsigned char* S_cut = NULL;
	//memcpy(S_cut,&D->state,l/8);
       return S_cut;
}






void
keypack(unsigned char** result,const unsigned char *key,unsigned long n_bits,
		unsigned long l){
	if ( n_bits > (255*8) || n_bits%8 ) exit(EXIT_FAILURE);
	int i;
	unsigned char*res = NULL;
	unsigned char *pad_key=NULL;
	unsigned long result_size;
	uint8_t B_val = l/8, padding=0x01;
	printf("****************Keypack stats***********\n");
	printf("*\tKeylen is %lu bits\n",n_bits);
	printf("*\tKeylen is %u bytes\n",BYTE_LEN(n_bits));
	printf("*\tThe value of l is %lu\n",l);
	printf("****************************************\n");
	*result = calloc(B_val,sizeof(char));
	res = calloc(B_val,sizeof(char));
	res[0] = B_val;
	memcpy(res+1,key,BYTE_LEN(n_bits));
	if (BYTE_LEN(n_bits)+1 <  B_val) 
		res[BYTE_LEN(n_bits)+1] = 0x01;

	memcpy(result,&res,B_val*sizeof(char));
	//free(res);
	return;
}

