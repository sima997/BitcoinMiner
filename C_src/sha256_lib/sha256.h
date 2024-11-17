#ifndef SHA256_H
#define SHA256_H

/*Defines*/
/*-----------------------------------------------------------------------------*/

#define BLOCK_SIZE          512 /*SHA256 block size [bits]*/
#define MESSAGE_LENGHT      64 /*Message per block length [bytes]*/
#define SHA256_ADD_1        8 /*Padding 10000 0000*/
#define MAX_SIZE_PER_BLOCK  (BLOCK_SIZE - MESSAGE_LENGHT - SHA256_ADD_1) /*Maximun size of message content in one sha256 block*/
#define UINT32_BYTES             sizeof(unsigned int) /*Number of bytes in uint32*/
#define UINT32_BITS        UINT32_BYTES*8 /*Number of bits in uint32*/

/*Types*/
/*-----------------------------------------------------------------------------*/

typedef unsigned short uint16_t;
typedef unsigned int uint32_t;

/*Variables*/
/*-----------------------------------------------------------------------------*/

/*Main structure data block*/
typedef struct {
    /*Number of block required of size = BLOCK_SIZE*/
    uint16_t block_count;
    /*Pointer to the data (32-bit unsigned integer) to hash*/
    char *data;
    /*Working wariable - TODO recomment*/
    uint32_t W[64];
    /*Next block*/
    uint16_t next_block;
    /*Array of prime numbers*/
    uint32_t primeArr[64];
    /*Hash values array*/
    uint32_t H[8];
    /*Constant array K*/
    uint32_t K[64];
    /*Working variables*/
    uint32_t a,b,c,d,e,f,g,h;
    /*String containing final hash output*/
    char hash[64];
    

}SHA256;

/*String holds final hash output*/
char s_hash[64];


/*Function prototypes*/
/*-----------------------------------------------------------------------------*/

/*Main control function*/
const char* sha256();

/*Test function*/
void test();

/*
Load variables W[0] - W[15]
*/
void init(SHA256 *m);

/*
Parse message into block
saved as string in memory
*/
void parse_message(SHA256 *m, char *message);

/*
Load variables W[0] - W[15]
*/
void load_W(SHA256 *m);

/*Compute W[16] - W[63]*/
void calc_W(SHA256 *m);
/*Initialize working variables*/
void init_working_variables(SHA256 *m);

/*Update working variables*/
void update_working_variables(SHA256 *m);

/*Update hash values*/
void update_hash_values(SHA256 *m);

/*Construct output hash string*/
void hash_string(SHA256 *m,char* dest);


/*Operations*/
/*-----------------------------------------------------------------------------*/

/*Right rotate operation*/
uint32_t right_rotate(uint32_t* data, uint16_t n);

/*Right shift operation*/
uint32_t right_shift(uint32_t* data, uint16_t n);

/*XOR operation*/
uint32_t xor(uint32_t* data, uint32_t* data2);

/*s0 operation*/
uint32_t s0(uint32_t* data);

/*s1 operation*/
uint32_t s1(uint32_t* data);

/*Sigma 0 operation*/
uint32_t E0(uint32_t* data);

/*E1 operation*/
uint32_t E1(uint32_t* data);

/*Get array of n prime numbers*/
void get_prime(SHA256 *m, size_t n);

/*
Calculate hash costants H
H is array of fractions of sqruare root of first 8 prime numbers
*/
void calc_prime_constants(SHA256 *m, char id);

/*
Free allocated data memory
*/
void deinit(SHA256 *m);

/*END sha256.h*/
#endif

