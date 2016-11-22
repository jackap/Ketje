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

printf("Calling Wrap again\n");
MonkeyWrapWrap(D,cryptogram,tag,t_len,data,168,header,h_len);
printf("Calling third time\n");
MonkeyWrapWrap(D,cryptogram,tag,t_len,data,0,header,208);
	//printf("Size of the algorithm is %u\n",D->n_stride);
	/* Implement this function */

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
/*****************************************************************************
 * @brief: This set of functions prints the content of a generic state array
 * @author: Jacopo Bufalino - jacopobufalino@gmail.com
 * @date: 2016/27/11 
 * @return: void 
 * @arg: inpunt state array
 * @note: Use them just to debug the code
 *
 *****************************************************************************/

void MonkeyWrapInitialize(Duplex *D, unsigned char *key, unsigned int k_len,
		unsigned char* seq_no,unsigned int seq_len){
	
	unsigned char *result=NULL,*data_2_feed=NULL;
	unsigned long result_len;
	unsigned int i;
	printf("MonkeyWrapInitialize\n");
	printf("Keylen is %u\n",k_len);
	printf("NonceLen is %u\n",seq_len);
	/*Create keypack, than concatenate it with the public sequence number */
	keypack(&result,key,k_len,k_len+16);
	result_len = k_len+16;
	printf("len after keypack is %u\n",k_len+16);

	//TODO Make the error on the constant suppress.

	if (seq_len != 0){
	unsigned int length;
		if (seq_len <=  (D->f - k_len - 18)) 
			length = seq_len;
		else 
			length = D->f - (k_len +18);
		result_len =
			concatenate(&data_2_feed,result,k_len+16,
			seq_no,length); 
		printf("Resulting len of the nonce: %lu == %lu\n",
				length,D->f - k_len - 18);
			
		for (i = 0 ; i < BYTE_LEN(result_len) ; i++)
			printf("%.2X ",data_2_feed[i]);
		
		DuplexStart(D,data_2_feed,result_len);
	}
	else 
		DuplexStart(D,result,result_len);
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

void MonkeyWrapWrap(Duplex *D,unsigned char *cryptogram, 
		unsigned char *tag, unsigned int t_len,
		unsigned char *data, unsigned long d_len,
		unsigned char *header, unsigned long h_len){

	/* Setup the number of blocks */

	



	unsigned long plain_blocks = ((d_len/D->rho)+(d_len%D->rho?1:0)),  
	header_blocks = h_len/D->rho;
	uint8_t i = 0;
	unsigned char* data_concatenated=NULL,*Z=NULL,*crypto = NULL;
	unsigned long data_size;
	unsigned long last_block_size = 0,last_plain =  d_len%D->rho;
	/* TODO*/
	crypto = calloc(BYTE_LEN(d_len),sizeof(unsigned char));

	printf("****************MonkeyWrapWrap stats***********\n");
	printf("*\tThere are %lu blocks of text d_len/D->rho \n",plain_blocks);
	printf("*\tData len d_len is  %lu\n",d_len);
	printf("*\tD->rho is %u\n",D->rho);
	printf("*\theader length is %u\n",h_len);
	printf("***********************************************\n");

	for ( i = 0  ; (i < (plain_blocks -2)) && (plain_blocks > 1) ; ++i)
	{
		printf("YOU SHOULD BE NOT HERE\n");
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


	unsigned char * data4second_step = NULL;
	unsigned int data_len;

	data_len = concatenate_01(&data4second_step,&data[plain_blocks -1],
			last_block_size);
	
	printf("data_len after concatenating_01 is: %u\n",data_len);
	printf("data is %.2x\n",data4second_step[0]);
	
	unsigned int B0 ;
	if (plain_blocks == 1) B0 = last_plain;
	else if (plain_blocks > 1) B0 = D->rho;
	else B0 = 0;

	 Z = DuplexStep(D,data4second_step,data_len,B0);
	 printf("\n---C0---\n");
	for ( i = 0 ; i < BYTE_LEN(B0) ; i++)
	{
		crypto[i] = data[i] ^ Z[i];
		//printf("%.2x ",crypto[i]);
	
	}
	free(Z);
	
	
	// at the end it will be equal to Z...
	printf("\nMONKEYDUPLEX state after stepping the last block of A:\n");
	for ( i = 0 ; i < (D->f/8) ; ++i)
		printf("%.2x ",D->state[i]);
	printf("\n");


	header_blocks = h_len/D->rho;unsigned char*temp_i = NULL;

	/* computing Ci+i */
	for (i = 0 ; (i <= plain_blocks - 2 ) && (plain_blocks > 1 ); i++)
	{
		concatenate_11(&temp_i,&data[i*BYTE_LEN(D->rho)],D->rho);

		Z = DuplexStep(D,temp_i,D->rho+2,D->rho);
		for (unsigned int j = 0 ; j < BYTE_LEN(D->rho) ; j++)
			crypto[BYTE_LEN(D->rho)*(i+1)+j] = 
				data[BYTE_LEN(D->rho)*(i+1)+j]^Z[i]; 
		/*printf("TODO: implement Ci\n");
		for ( int j = 0 ; j < BYTE_LEN(D->rho) ; ++j)
		printf("%.2x ",temp_i[j]);
	printf("\n");*/
	
	
	}
	printf("\nMONKEYDUPLEX statiie after for B......:\n");
	for ( i = 0 ; i < (D->f/8) ; ++i)
		printf("%.2x ",D->state[i]);
	printf("\n");

free(data4second_step);
	data_len = concatenate_10(&data4second_step,data, last_block_size);

//EDIT :
unsigned char dummy = 0x10;
unsigned char *temp_tag;
unsigned int temp_tag_len = D->rho;
unsigned char *ttag;
unsigned long ttag_len;
unsigned char*in_put;
concatenate_10(&in_put,&data[(plain_blocks-1)*BYTE_LEN(D->rho)],last_plain);
printf("++++++++++++++++++++++++++\n");
for ( i = 0 ; i < BYTE_LEN(last_plain+2) ; ++i)
		printf("%.2x ",in_put[i]);
	printf("\n++++++++++++++++++++++++\n");
temp_tag = DuplexStride(D,in_put,last_plain+2,D->rho);
	printf("\nMONKEYDUPLEX statiie after stepping the last block of B:\n");
	for ( i = 0 ; i < (D->f/8) ; ++i)
		printf("%.2x ",D->state[i]);
	printf("\n");
unsigned char* tmp;
while (temp_tag_len < 128){
	printf("ANOMAL CASE ************************* \n ABORT");
	exit(1);
	concatenate(&tmp,temp_tag,D->rho,DuplexStep(D,NULL,0,D->rho),D->rho);
	
}	
printf("\n\n+++++++++TAG+++++++++++\n\n");	
for (int i = 0 ; i < BYTE_LEN(128) ; i++)
	printf("%.2X ",temp_tag[i]);
printf("\n");
printf("\n\n+++++++++CRYPTO+++++++++++\n\n");	
for (int i = 0 ; i < BYTE_LEN(d_len) ; i++)
	printf("%.2X ",crypto[i]);
printf("\n");




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
DuplexStart(Duplex *D,unsigned char *I,unsigned long i_len){
	printf("Inside DuplexStart\n");
	unsigned char *padding=NULL,*state=NULL;
	unsigned long pad_len;
	/* Add padding */
	printf("D->f:%u, I_len:%u\n",D->f, i_len);
	if (i_len%D->f){
		pad_len = pad10x1(&padding,D->f,i_len);
		printf("After padding\n");
	unsigned long result = 	concatenate(&state,I,i_len,padding,pad_len);
		printf("After concatenate, the length is: %lu\n",result);
		printf("STATE BEFORE KECCAK_P_STAR\n");
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
	   for (int i = 0 ; i < 200 ; i++)
	   printf("%.2x ",D->state[i]);
	   printf("\n\n");
	  
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

unsigned char*
DuplexStep(Duplex *D, unsigned char *sigma,unsigned long s_len,
		unsigned long l){

	unsigned char *pad=NULL,*P=NULL;
	unsigned long pad_len,P_len,Pc_len;
	/* concatenate padding to the input string sigma*/
	pad_len = pad10x1(&pad, D->r,s_len);
	P_len = concatenate(&P,sigma,s_len,pad,pad_len);

	/*for (unsigned int i = 0 ; i < P_len/8 +1 ; i++)
		printf("%.2x ",P[i]);
	printf("\n");*/

	/* xor the current state with the new string  */
	for (uint8_t i = 0 ; i < BYTE_LEN(P_len)  ; ++i ) 
		D->state[i] = D->state[i] ^ P[i];
/*	
printf("After the xor\n");
	for (unsigned int i = 0 ; i < 200 ; i++)
		printf("%.2x ",D->state[i]);
	printf("\n");*/



	printf("****************DuplexStep stats***********\n");
	printf("*\tSigma len is %lu bits\n",s_len);
	printf("*\tThe value of l is %lu\n",l);
	printf("*\tPadding len is %lu\n",pad_len);
	printf("*\tP string len is %lu\n",P_len);
	printf("*\tb-r is %lu\n",D->f- D->r);
	printf("****************************************\n");

	/* apply keccak_p_star function */
	unsigned char * state = keccak_p_star(D->state,D->rho,
			D->n_step,D->f);

	/* copy the output of keccak to the current state */
	free(D->state);
	D->state = state;
	/* duplicate the state array and truncate it up to l bits */
	char * ret_val = calloc(BYTE_LEN(l),sizeof(char));
	memcpy(ret_val,state,BYTE_LEN(l)*sizeof(char));
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

unsigned char*
DuplexStride(Duplex *D, unsigned char *sigma,unsigned long s_len,
		unsigned long l){
	
	
	unsigned char *pad=NULL,*P=NULL;
	unsigned long pad_len,P_len,Pc_len;
	/* concatenate padding to the input string sigma*/
	pad_len = pad10x1(&pad, D->r,s_len);
	P_len = concatenate(&P,sigma,s_len,pad,pad_len);

	/*for (unsigned int i = 0 ; i < P_len/8 +1 ; i++)
		printf("%.2x ",P[i]);
	printf("\n");*/

	/* xor the current state with the new string  */
	for (uint8_t i = 0 ; i < BYTE_LEN(P_len)  ; ++i ) 
		D->state[i] = D->state[i] ^ P[i];
/*	
printf("After the xor\n");
	for (unsigned int i = 0 ; i < 200 ; i++)
		printf("%.2x ",D->state[i]);
	printf("\n");*/



	printf("****************DuplexStride stats***********\n");
	printf("*\tSigma len is %lu bits\n",s_len);
	printf("*\tThe value of l is %lu\n",l);
	printf("*\tPadding len is %lu\n",pad_len);
	printf("*\tP string len is %lu\n",P_len);
	printf("*\tb-r is %lu\n",D->f- D->r);
	printf("****************************************\n");

	/* apply keccak_p_star function */
	unsigned char * state = keccak_p_star(D->state,D->rho,
			D->n_stride,D->f);

	/* copy the output of keccak to the current state */
	free(D->state);
	D->state = state;
	/* duplicate the state array and truncate it up to l bits */
	char * ret_val = calloc(BYTE_LEN(l),sizeof(char));
	memcpy(ret_val,state,BYTE_LEN(l)*sizeof(char));
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
keypack(unsigned char** result,const unsigned char *key,unsigned long n_bits,
		unsigned long l){
	if ( n_bits > (255*8) || n_bits%8 ) exit(EXIT_FAILURE);
	

	unsigned char*res = NULL,*simple_pad = NULL,*pad_key=NULL;
	unsigned long result_size,l_conc;
	uint8_t B_val = l/8, padding=0x01;
	/* concatenate enc(l/8) with the key */
	result_size = concatenate(&pad_key,&B_val, 8 ,key, n_bits);
	if (result_size <= 0 ) exit(EXIT_FAILURE);
	/* concatenate 0x01 to the previous string */
	result_size = concatenate(&res,pad_key,n_bits +8, &padding,8);
	/* create an empty array of the desired size l-result_size 
	 * and concatenate it to the previous one to get the final
	 * result */
	simple_pad =
		calloc(BYTE_LEN(l-result_size),sizeof(unsigned char));
	
	l_conc = 
		concatenate(result,res,result_size,simple_pad,l-result_size);
	printf("Len of the array after keypack is: %lu\n",l_conc);
	printf("****************Keypack stats***********\n");
	printf("*\tKeylen is %lu bits\n",n_bits);
	printf("*\tKeylen is %u bytes\n",BYTE_LEN(n_bits));
	printf("*\tThe first byte of the new array should be %.2X\n",B_val);
	printf("****************************************\n");
	free(res);
	free(pad_key);
	free(simple_pad);
	return;
}

