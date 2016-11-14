#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
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

typedef struct mnk_D {
unsigned int f,rho,n_start,n_stride,n_step,b;
unsigned long state_len;
char * state;
}Duplex_object;

void
MonkeyDuplexStart(Duplex_object *D,char * I,unsigned int n_bits);
void
MonkeyDuplexInit(Duplex_object *D,unsigned int permutation,
unsigned int n_start, unsigned int n_step, unsigned int n_stride);
char*
MonkeyWrapInitialize(Duplex_object *D,const unsigned char *key,
unsigned int k_len,unsigned int seq_no);
void
MonkeyWrap(Duplex_object *D, unsigned char *cryptogram,
		unsigned char *tag, unsigned int t_len,
		const unsigned char *key, unsigned int k_len,
		const unsigned char *nonce, unsigned int n_len,
		const unsigned char *data, unsigned long d_len,
		const unsigned char *header, unsigned long h_len);

void
keypack(char** result,char *key,unsigned long n_bits,unsigned long l);
















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

	/* Implement this function */
Duplex_object *D;
MonkeyDuplexInit(D,1600,12,1,6);

MonkeyWrap(D,cryptogram,tag, t_len,key,
k_len,nonce,n_len,data, d_len,header, h_len);

	return;
}

void
MonkeyWrap(Duplex_object *D, unsigned char *cryptogram,
		unsigned char *tag, unsigned int t_len,
		const unsigned char *key, unsigned int k_len,
		const unsigned char *nonce, unsigned int n_len,
		const unsigned char *data, unsigned long d_len,
		const unsigned char *header, unsigned long h_len)
{
//MonkeyInit must be done in ketje! DONE 
// Input header + body -> Output crypto + tag

//Concatenate header and nonce to create I 
char *I,*wrap_init_output;
int i = 0 ;
// The content is stored inside the Dect
unsigned long i_len  = concatenate(I,header,h_len,nonce,n_len);
printf("Concatendated header and nonce\n");
//MonkeyWrap initialized
MonkeyWrapInitialize(D,I,i_len,0);
//
for (i = 0 ; i < 30 ; i++){
	printf("%.2x ", D->state[i]);


}

//MonkeyDuplexStep();


}

void
MonkeyWrap_Wrap(char *data, unsigned long d_len. char * message,unsigned long m_len
unsigned long strength){
//Data message strength


}

void
MonkeyWrapInitialize(Duplex_object *D,const unsigned char *key,
		unsigned int k_len,unsigned int seq_no)
{
//Security controls... TODO
unsigned char *keyp,*I;
unsigned char *dummy = malloc(sizeof(char));
dummy = seq_no;
printf("Calling keypack to generate the pack");
keypack(keyp,key,k_len + 16 ,D->f);
unsigned int total_len = concatenate(I,keyp,D->f,dummy,8);
printf("Concatenated keypack with seq. no");
MonkeyDuplexStart(D,I,total_len);
}
void
MonkeyDuplexInit(Duplex_object *D,unsigned int permutation,
unsigned int n_start, unsigned int n_step, unsigned int n_stride){

/*
 Implement
 */

D = malloc(sizeof(Duplex_object));
D->f = permutation;
D->n_start = n_start;
D->n_stride = n_stride;
D->n_step = n_step;
D->rho = 256; //create a definition TODO

}

//char *
void
MonkeyDuplexStart(Duplex_object *D,char * I,unsigned int n_bits)
{
char * s,*p;
/*
 * If necessary add padding
 * Then apply keccak function
 *
 * */
printf("Called MonkeyDuplexStart");
if (n_bits % D->f){
	unsigned int len = (unsigned int) pad10x1(p,D->f,n_bits);
	concatenate(s,I,n_bits,p,len);
}
else{
	s = I;

}
// Do implementation of keccak
//return keccak_p_star(s,D.f,obj.n_start,obj.b);
D->state = keccak_p_star(s,D->f,D->n_start,D->b);
}
//Sigma can be some seed or can be null
//in the latter case I suppose that sigma_len is 0 

void
MonkeyDuplexStep(Duplex_object *D,char * I,char *sigma,unsigned int sigma_len, unsigned int l){}

void
MonkeyDuplexStride(Duplex_object *D,char * I,char *sigma,unsigned int sigma_len, unsigned int l){}




void
keypack(char** result,char *key,unsigned long n_bits,unsigned long l){
if ( n_bits > (255*8) || n_bits%8 ) exit(EXIT_FAILURE);
unsigned char *pad_key,*padding;
unsigned long result_size;
const unsigned char B_val = (const unsigned char) l/8;
// you cannot have  %8 != 0
result_size = concatenate(pad_key,&B_val,(unsigned long) 8, key,n_bits);
if (result_size <= 0 ) exit(EXIT_FAILURE);
result_size = pad10x1(padding,l,n_bits + 8);
//alignment value is l but I have already key + n_BYTES
if (result_size <= 0 ) exit(EXIT_FAILURE);
result_size = concatenate(result,pad_key,n_bits +8, padding,result_size);
//now keypack should be completed.
free(pad_key);
free(padding);
return;
}




