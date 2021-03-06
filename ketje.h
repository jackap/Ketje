#ifndef KETJE_H
#define KETJE_H

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

typedef struct m_obj {
unsigned int f,n_start,n_step,n_stride,rho,r;
unsigned char *state;
} Duplex;

Duplex*
DuplexInit(unsigned int f,unsigned int rho,unsigned int n_start,
		unsigned int n_step,unsigned int n_stride);

void
DuplexStart(Duplex *D,unsigned char *I,unsigned long i_len);

unsigned char*
DuplexStep(Duplex *D, unsigned char *sigma,unsigned long s_len,
		unsigned long l);
unsigned char*
DuplexStride(Duplex *D, unsigned char *sigma,unsigned long s_len,
		unsigned long l);

void MonkeyWrapInitialize(Duplex *D, const unsigned char *key, unsigned int k_len,
		const unsigned char *seq_no,unsigned int seq_len);
void MonkeyWrapWrap(Duplex *D,unsigned char *cryptogram, 
		unsigned char *tag, unsigned int t_len,
		const unsigned char *data, unsigned long d_len,
		const unsigned char *header, unsigned long h_len);


void
MonkeyWrap(Duplex *D, unsigned char *cryptogram,
		unsigned char *tag, unsigned int t_len,
		const unsigned char *key, unsigned int k_len,
		const unsigned char *nonce, unsigned int n_len,
		const unsigned char *data, unsigned long d_len,
		const unsigned char *header, unsigned long h_len);



void ketje_mj_e(unsigned char *cryptogram,
		unsigned char *tag, unsigned int t_len,
		const unsigned char *key, unsigned int k_len,
		const unsigned char *nonce, unsigned int n_len,
		const unsigned char *data, unsigned long d_len,
		const unsigned char *header, unsigned long h_len);

/* You can add your own functions below this line.
 * Do NOT modify anything above. */
void
keypack(unsigned char** result,const unsigned char *key,unsigned long n_bits,
		unsigned long l);
#endif				/* KETJE_H */
