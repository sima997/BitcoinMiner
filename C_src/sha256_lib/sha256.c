#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <float.h>
#include "sha256.h"


const char* sha256(char* message)
{
    SHA256 sha256;
    /*Get array of first 64 prime numbers*/
    get_prime(&sha256,64);
    /*Initialize variables*/
    init(&sha256);
    /*Parse and pad input message into 512-bit blocks*/
    parse_message(&sha256, message);
    /*Repeat algoritm for each 512-bit block*/
    for(size_t i=0;i<sha256.block_count;i++)
    {
        /*Load message into W[0..15] array*/
        load_W(&sha256);
        /*Calculate W[16..63]*/;
        calc_W(&sha256);
        /*Initialize working variables a,b,c,d,e,f,g,h*/
        init_working_variables(&sha256);
        /*Update working variables a,b,c,d,e,f,g,h*/
        update_working_variables(&sha256);
        /*Update hash array H[0..7]*/
        update_hash_values(&sha256);
    }
    /*Create output string*/
    hash_string(&sha256,&s_hash[0]);

    /*Free the memory*/
    deinit(&sha256);

    /*Returns pointer to the has string*/
    return &s_hash[0];
}

void init(SHA256 *m)
{
    /*Initialize next block to start*/
    m->next_block = 0;
    /*Initialize hash values*/
    /*
    m->H[0] = (uint32_t)H0;
    m->H[1] = (uint32_t)H1;
    m->H[2] = (uint32_t)H2;
    m->H[3] = (uint32_t)H3;
    m->H[4] = (uint32_t)H4;
    m->H[5] = (uint32_t)H5;
    m->H[6] = (uint32_t)H6;
    m->H[7] = (uint32_t)H7;
    */
    /*Prepare first 64 prime numbers*/
    get_prime(m,64);
    /*Initialize hash constant H*/
    calc_prime_constants(m,'H');
    /*Initialize hash constant K*/
    calc_prime_constants(m,'K');
    /*Initialize working variables to H*/
    //init_working_variables(m);
    
}

void parse_message(SHA256 *m, char *message)
{
    /*
    One block must be 512-bits long
    Last block message content:
        440-bit of message
        8-bit identifier (1 an MSB)
        64-bit message original length    
    */
    
    /*Amount of numbers in the message. One character (hex) = 4-bit*/
    size_t s_msg_size = strlen(message);
    /*Pointer to the start of the message*/
    char *ptr_start = &message[0]; 


    printf("Message size is %d\n",s_msg_size);
    printf("Which is %d bytes\n",s_msg_size/2);
    printf("Which is %d bits\n",s_msg_size/2*8);

    /*
    Check how many block of size BLOCK_SIZE are required    
    */
    if((s_msg_size*4)%BLOCK_SIZE <= MAX_SIZE_PER_BLOCK)
    {
        printf("Last block fits in %d bits\n",(unsigned int)BLOCK_SIZE);
        m->block_count = (s_msg_size/2*8)/BLOCK_SIZE + 1;
    }else
    {
        printf("Last block does not fit in %d bits, extending\n",(unsigned int)BLOCK_SIZE);
        m->block_count = (s_msg_size/2*8)/BLOCK_SIZE + 2;

    }

      
    /*
    Data comes as a string message of n characters.
    Block of block_count*BLOCK_SIZE of chars '0' can be alocated and message coppied into it
    */

   /*Space allocation*/
   size_t block = m->block_count*BLOCK_SIZE*sizeof(char);
   printf("Allocating %d\n",block);
    m->data = (char*)malloc(block);
    memset(m->data,'0',block);
    strncpy(m->data,message,s_msg_size);

    /*
    Add 8'b10000 0000 after the message
    1<<7 = 0x80
    */
    char msg_terminator[2] = "80";
    strncpy(m->data+s_msg_size,msg_terminator,2);

    /*
    Message size signature
    */
    char msg_len[8];
    sprintf(&msg_len[0],"%x",s_msg_size*4);
    printf("Message len in hex is %s\n",msg_len);
    strncpy(m->data+block/4-strlen(msg_len),msg_len,8);
    

}

void load_W(SHA256 *m)
{
    assert(m->next_block<m->block_count);
    char *ptr = m->data + m->next_block*BLOCK_SIZE/4;
    for(size_t i=0;i<16;i++)
    {
        char temp[8];
        strncpy(&temp[0],ptr,8);
        m->W[i] = strtoul(&temp[0],NULL,16);
        ptr += 8;
    }

     m->next_block++;

}


/*Compute W[16] - W[63]*/
void calc_W(SHA256 *m)
{
    for(size_t i = 0;i<48;i++)
    {
        m->W[i+16] = m->W[i] + s0(&m->W[i+1]) + m->W[i+9] + s1(&m->W[i+14]);
    }
    
}


uint32_t right_rotate(uint32_t* data, uint16_t n)
{
    return (*data >> n) | (*data << (UINT32_BITS - n));
}

uint32_t right_shift(uint32_t* data, uint16_t n)
{

    return *data>>n;
}

uint32_t xor(uint32_t* data1, uint32_t* data2)
{
    return *data1 ^ *data2;
}

uint32_t s0(uint32_t* data)
{
    uint32_t temp[3];
    temp[0] = right_rotate(data,7);
    temp[1] = right_rotate(data,18);
    temp[2] = right_shift(data,3);
    temp[0] = xor(&temp[0],&temp[1]);
    temp[0] = xor(&temp[0],&temp[2]);
    return temp[0];

}

uint32_t s1(uint32_t* data)
{
    uint32_t temp[3];
    temp[0] = right_rotate(data,17);
    temp[1] = right_rotate(data,19);
    temp[2] = right_shift(data,10);
    temp[0] = xor(&temp[0],&temp[1]);
    temp[0] = xor(&temp[0],&temp[2]);
    return temp[0];

}

uint32_t E0(uint32_t* data)
{
    uint32_t temp[3];
    temp[0] = right_rotate(data,2);
    temp[1] = right_rotate(data,13);
    temp[2] = right_rotate(data,22);
    temp[0] = xor(&temp[0],&temp[1]);
    temp[0] = xor(&temp[0],&temp[2]);
    return temp[0];

}

uint32_t E1(uint32_t* data)
{
    uint32_t temp[3];
    temp[0] = right_rotate(data,6);
    temp[1] = right_rotate(data,11);
    temp[2] = right_rotate(data,25);
    temp[0] = xor(&temp[0],&temp[1]);
    temp[0] = xor(&temp[0],&temp[2]);
    return temp[0];

}

void get_prime(SHA256 *m, size_t n)
{
    /*
    Prime numbers can be divided only by 1 or itself
    */
    uint16_t prime_count = 0;
    uint16_t is_prime = 1;
    uint32_t prime_counter = 2;
    while(prime_count < n)
    {
        uint32_t prime_sqrt = (uint32_t)floor(sqrt(prime_counter));
        is_prime = 1;
        for(size_t i = 2;i<=prime_sqrt;i++)
        {
            if(prime_counter%i==0)
            {
                is_prime = 0;
                
            }
        }
        if(is_prime && prime_counter > 1)
        {
            //printf("Prime = %d\n",prime_counter);
            m->primeArr[prime_count] = prime_counter;
            prime_count++;
        }
        prime_counter++;
    }
}

/*
Calculate hash costants H[8] and K[64]
H is array of fractions of sqruare root of first 8 prime numbers
K is array of fractions of cube root of first 8 prime numbers
*/
void calc_prime_constants(SHA256 *m, char id)
{
    double temp;
    double dummy;
    char data[8];
    size_t range = 0;
    uint32_t *destination;

    if(id == 'H')
    {
        range = sizeof(m->H)/sizeof(uint32_t);
        destination = m->H;
    }else if(id == 'K')
    {
        range = sizeof(m->K)/sizeof(uint32_t);
        destination = m->K;
    } 

    //printf("range is %d",range);
    
    
    for(size_t i =0;i<range;i++)
    {
        
         if(id == 'H')
        {
            temp = modf(sqrt(m->primeArr[i]),&dummy);
        }else if(id == 'K')
        {
            temp = modf(cbrt(m->primeArr[i]),&dummy);
        }
        //printf("Fractional part is %.20lf\n",temp);
        for(size_t j = 0;j<8;j++)
        {
            
            temp *=16;
            //printf("Res = %lf\n",temp);
            sprintf(&data[0]+j,"%x",(unsigned int)temp);
            temp = modf(temp,&dummy);
            
            
        }
        //printf("String is %s\n",&data[0]);
        //TODO - rework and optimize
        *(destination + i) = strtoul(&data[0],NULL,16);
        

    }
}

void init_working_variables(SHA256 *m)
{
    m->a = m->H[0];
    m->b = m->H[1];
    m->c = m->H[2];
    m->d = m->H[3];
    m->e = m->H[4];
    m->f = m->H[5];
    m->g = m->H[6];
    m->h = m->H[7];

}

void update_working_variables(SHA256 *m)
{
    uint32_t Temp1, Temp2, Choice, Majority;

    for(size_t i = 0;i<64;i++)
    {   
        
        /*Choice = (e and f) xor ((not e) and g)*/
        Choice = (m->e & m->f)^(~(m->e) & m->g);
        Temp1 = m->h + E1(&m->e) + Choice + m->K[i] + m->W[i]; 
        //printf("E1(%x) = %x\n",m->e,E1(&m->e));
        /*Majority =(a and b) xor (a and c) xor (b and c)*/
        Majority = (m->a & m->b) ^ (m->a & m->c) ^ (m->b & m->c);      
        Temp2 = E0(&m->a) + Majority;
        //printf("E0(%x) = %x\n",m->a,E0(&m->a));
        //printf("a = %x, b = %x, c = %x, d = %x, e = %x, f = %x, g = %x, h = %x\n",m->a, m->b,m->c,m->d,m->e,m->f,m->g,m->h);
        m->h = m->g;
        m->g = m->f;
        m->f = m->e;
        m->e = m->d + Temp1;
        m->d = m->c;
        m->c = m->b;
        m->b = m->a;      
        m->a = Temp1 + Temp2;

        //printf("Choice = %x, Majority = %x, Temp1 = %x, Temp2 = %x\n",Choice,Majority,Temp1,Temp2);
        
        //printf("a = %x, b = %x, c = %x, d = %x, e = %x, f = %x, g = %x, h = %x\n",m->a, m->b,m->c,m->d,m->e,m->f,m->g,m->h);
    }
}

/*Update hash values*/
void update_hash_values(SHA256 *m)
{
    m->H[0] += m->a;
    m->H[1] += m->b;
    m->H[2] += m->c;
    m->H[3] += m->d;
    m->H[4] += m->e;
    m->H[5] += m->f;
    m->H[6] += m->g;
    m->H[7] += m->h;
}

void hash_string(SHA256 *m,char *dest)
{
    sprintf(dest,"%x%x%x%x%x%x%x%x",m->H[0],m->H[1],m->H[2],m->H[3],m->H[4],m->H[5],m->H[6],m->H[7]);
}


void test()
{
    uint32_t data1 = 0xABCBABCB;
    uint32_t data2 = 0x12345678;
    uint32_t W1 = 0xE421104E;
    uint32_t W14 = 0x7DBC34AE;
    uint32_t a = 0x6A09E667;
    uint32_t e = 0x510E527F;
    
    uint16_t n = 5;
    printf("------------------------------------\n");
    printf("Self test start\n");

    /*Test XOR operation*/
    assert(xor(&data1,&data2) == 0xB9FFFDB3);
    printf("XOR function test pass\n");

    /*Test Right rotate operation*/
    assert(right_rotate(&data1,n) == 0x5D5E5D5E);
    printf("Right rotation pass\n");

    /*Test Right shift operation*/
    assert(right_shift(&data1,n) == (data1>>n));
    printf("Right shift pass\n");

    /*Test s0*/
    assert(s0(&W1) == 0xC55FD921);
    printf("sigma 0 function pass\n");

    /*Test s1*/
    assert(s1(&W14) == 0x9CDD9E64);
    printf("sigma 1 function pass\n");

    /*Test E0*/
    assert(E0(&a) == 0xCE20B47E);
    printf("Sigma 0 function pass\n");

    /*Test E1*/
    assert(E1(&e) == 0x3587272B);
    printf("Sigma 1 function pass\n");

    printf("Self test end\n");
    printf("------------------------------------\n");
    
}

void deinit(SHA256 *m)
{
    free(m->data);
}