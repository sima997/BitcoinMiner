#include <stdio.h>
#include <string.h>
#include "sha256.h"

//SHA256 sha256;

int main(int argc, char *argv[])
{

    test();
    const char* out = sha256(argv[1]);
    printf("%s", out);
    /*
    get_prime(&sha256,64);

    init(&sha256);

    for(size_t i =0;i<8;i++)
    {
        printf("H[%d] = %x\n",i,sha256.H[i]);
    }

    for(size_t i =0;i<64;i++)
    {
        printf("K[%d] = %x\n",i,sha256.K[i]);
    }

    parse_message(&sha256, argv[1]);

    printf("%d\n",sha256.block_count);

    printf("%s\n",sha256.data);
    load_W(&sha256);
    //load_W(&sha256);
    calc_W(&sha256);


    for(size_t i=0;i<64;i++)
    {
        //printf("W[%d] in dec = %ld, in hex = %x\n",i,sha256.W[i],sha256.W[i]);
    }

    init_working_variables(&sha256);
    update_working_variables(&sha256);
    update_hash_values(&sha256);

    for(size_t i = 0;i<8;i++)
    {
        printf("H[%d] = %x\n",i, sha256.H[i]);
    }

    load_W(&sha256);
    //load_W(&sha256);
    calc_W(&sha256);

    for(size_t i=0;i<64;i++)
    {
        printf("W[%d] in dec = %ld, in hex = %x\n",i,sha256.W[i],sha256.W[i]);
    }

    init_working_variables(&sha256);
    update_working_variables(&sha256);
    update_hash_values(&sha256);
    printf("---------------------------------------\n");
    for(size_t i = 0;i<8;i++)
    {
        printf("H[%d] = %x\n",i, sha256.H[i]);
    }

    deinit(&sha256);
    */

    return 0;
}
