/***************************************************************************************************************************************
 * FILE NAME: sha1.c
 *
 * Copyright (c)  2016 Anders Nordenfelt
 *
 * DATED: 2016-09-03
 *
 * CONTENT: Implements the SHA1 hash algorithm and its corresponding HMAC-SHA1 function in accordance with the 
 *          NIST specifications (FIPS PUB 180-4) and (FIPS PUB 198-1).
 *
 **************************************************************************************************************************************/
    
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "shalib.h"
#include "sha1.h"

#define BLOCK_SIZE 64       /* defines the size of a block in BYTES                                     */ 
#define WORD_SIZE 4         /* defines the size of a word in BYTES                                      */
#define HASH_SIZE 5         /* defines the size of the hash in number of 32-bit INTEGERS                */



/************************************************************************************************************/

/* The function SHA1_Iterate_Hash implements the SHA1 hash iteration function. 
   See the NIST documentation (FIPS PUB 180-4) for details. 
   This part of the code has been optimized for speed */


void SHA1_Iterate_Hash(struct sha_word_pointer *p, uint32_t *H)
{
    #define Rot_Left(t, x) (((x) << t) | ((x) >> (32 - t)))
    #define Ch(x, y, z) ((x & y) ^ (~x & z))
    #define Parity(x, y, z) (x ^ y ^ z)
    #define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

    #define F1(a, b, c, d, e, x)                                    \
    {                                                               \
        e += Rot_Left(5, a) + Ch(b, c, d) + 0x5a827999 + x;         \
        b =  Rot_Left(30, b);                                       \
    }

    #define F2(a, b, c, d, e, x)                                    \
    {                                                               \
        e += Rot_Left(5, a) + Parity(b, c, d) + 0x6ed9eba1 + x;     \
        b = Rot_Left(30, b);                                        \
    }

    #define F3(a, b, c, d, e, x)                                    \
    {                                                               \
        e += Rot_Left(5, a) + Maj(b, c, d) + 0x8f1bbcdc + x;        \
        b = Rot_Left(30, b);                                        \
    }

    #define F4(a, b, c, d, e, x)                                    \
    {                                                               \
        e += Rot_Left(5, a) + Parity(b, c, d) + 0xca62c1d6 + x;     \
        b = Rot_Left(30, b);                                        \
    }

    #define U(i)  (W[i] = Rot_Left(1, W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16]), W[i])

    uint32_t W[80], a, b, c, d, e;

    Load_32Int_Buffer(p, W);

    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];

    F1(a, b, c, d, e, W[0]);
    F1(e, a, b, c, d, W[1]);
    F1(d, e, a, b, c, W[2]);
    F1(c, d, e, a, b, W[3]);
    F1(b, c, d, e, a, W[4]);
    F1(a, b, c, d, e, W[5]);
    F1(e, a, b, c, d, W[6]);
    F1(d, e, a, b, c, W[7]);
    F1(c, d, e, a, b, W[8]);
    F1(b, c, d, e, a, W[9]);
    F1(a, b, c, d, e, W[10]);
    F1(e, a, b, c, d, W[11]);
    F1(d, e, a, b, c, W[12]);
    F1(c, d, e, a, b, W[13]);
    F1(b, c, d, e, a, W[14]);
    F1(a, b, c, d, e, W[15]);
    F1(e, a, b, c, d, U(16));
    F1(d, e, a, b, c, U(17));
    F1(c, d, e, a, b, U(18));
    F1(b, c, d, e, a, U(19));

    F2(a, b, c, d, e, U(20));
    F2(e, a, b, c, d, U(21));
    F2(d, e, a, b, c, U(22));
    F2(c, d, e, a, b, U(23));
    F2(b, c, d, e, a, U(24));
    F2(a, b, c, d, e, U(25));
    F2(e, a, b, c, d, U(26));
    F2(d, e, a, b, c, U(27));
    F2(c, d, e, a, b, U(28));
    F2(b, c, d, e, a, U(29));
    F2(a, b, c, d, e, U(30));
    F2(e, a, b, c, d, U(31));
    F2(d, e, a, b, c, U(32));
    F2(c, d, e, a, b, U(33));
    F2(b, c, d, e, a, U(34));
    F2(a, b, c, d, e, U(35));
    F2(e, a, b, c, d, U(36));
    F2(d, e, a, b, c, U(37));
    F2(c, d, e, a, b, U(38));
    F2(b, c, d, e, a, U(39));

    F3(a, b, c, d, e, U(40));
    F3(e, a, b, c, d, U(41));
    F3(d, e, a, b, c, U(42));
    F3(c, d, e, a, b, U(43));
    F3(b, c, d, e, a, U(44));
    F3(a, b, c, d, e, U(45));
    F3(e, a, b, c, d, U(46));
    F3(d, e, a, b, c, U(47));
    F3(c, d, e, a, b, U(48));
    F3(b, c, d, e, a, U(49));
    F3(a, b, c, d, e, U(50));
    F3(e, a, b, c, d, U(51));
    F3(d, e, a, b, c, U(52));
    F3(c, d, e, a, b, U(53));
    F3(b, c, d, e, a, U(54));
    F3(a, b, c, d, e, U(55));
    F3(e, a, b, c, d, U(56));
    F3(d, e, a, b, c, U(57));
    F3(c, d, e, a, b, U(58));
    F3(b, c, d, e, a, U(59));

    F4(a, b, c, d, e, U(60));
    F4(e, a, b, c, d, U(61));
    F4(d, e, a, b, c, U(62));
    F4(c, d, e, a, b, U(63));
    F4(b, c, d, e, a, U(64));
    F4(a, b, c, d, e, U(65));
    F4(e, a, b, c, d, U(66));
    F4(d, e, a, b, c, U(67));
    F4(c, d, e, a, b, U(68));
    F4(b, c, d, e, a, U(69));
    F4(a, b, c, d, e, U(70));
    F4(e, a, b, c, d, U(71));
    F4(d, e, a, b, c, U(72));
    F4(c, d, e, a, b, U(73));
    F4(b, c, d, e, a, U(74));
    F4(a, b, c, d, e, U(75));
    F4(e, a, b, c, d, U(76));
    F4(d, e, a, b, c, U(77));
    F4(c, d, e, a, b, U(78));
    F4(b, c, d, e, a, U(79));

    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
}

/*------------------------------------------------------------------------------------------------------------------------------*/

void SHA1_Compute(struct sha_word_pointer *p, uint32_t *hash)
{
    const uint32_t H_init[] = {0x67452301,       /* Initial SHA1 hash vector */
                               0xefcdab89,
                               0x98badcfe,
                               0x10325476,
                               0xc3d2e1f0};  
    uint32_t H[HASH_SIZE];
    uint64_t N;
    int i;

    /* Initiate the hash */

    for (i = 0; i < HASH_SIZE; i++)
        H[i] = H_init[i];

    /* Iterate the hash */

    N = p->tot_byte_size/BLOCK_SIZE;
    for (i = 0; i < N; i++)
        SHA1_Iterate_Hash(p, H);

    /* Store final hash */

    for (i = 0; i < HASH_SIZE; i++)
        hash[i] = H[i];
}

/*********************************************************************************************************************************
 *
 * FUNCTION NAME: SHA1_Concat
 *
 * PURPOSE: Takes as an argument a collection of char arrays, performs a virtual concatenation of these arrays in
 *          the order they appear, implements the SHA1 algorithm on the concatenated array and stores the resulting hash.
 *
 * ARGUMENTS:
 *
 * ARGUMENT            TYPE            I/O     DESCRIPTION
 * --------            ----            ---     -----------
 * strings             char**          I       the pointer to the char* array containing the pointers to the char arrays 
 *                                             to be hashed as a concatenation
 * nr_of_strings       uint64_t        I       the number of char arrays in the concatenation
 * strings_byte_size   uint64_t*       I       pointer to the uint64_t array containing the size in bytes of each char array 
 * hash                uint32_t*:      O       pointer to the uint32_t array where the resulting hash is to be stored
 *
 * RETURN VALUE : void
 *
 *********************************************************************************************************************************/

void SHA1_Concat(char **strings, uint64_t nr_of_strings, uint64_t *strings_byte_size, uint32_t *hash)
{
    int i;                          
    uint64_t concat_byte_size;                   /* the size in bytes of the total string concatenation     */
    unsigned char pad[BLOCK_SIZE + 9];           /* the pad                                                 */
    struct sha_word_pointer p;                   /* the word pointer                                        */

    /* Initiate the word pointer */

    Set_Zero(&p);
    p.strings = strings;
    p.nr_of_strings = nr_of_strings;
    p.strings_byte_size = strings_byte_size;

    /* Calculate the total byte-size of the string concatenation and set the pad */

    concat_byte_size = 0;
    for (i = 0; i < nr_of_strings; i++)
        concat_byte_size = concat_byte_size + strings_byte_size[i];
    Set_64Byte_Pad(&p, pad, concat_byte_size);

    /* Compute the hash */

    SHA1_Compute(&p, hash);
}

/********************************************************************************************************************************
 *
 * FUNCTION NAME: SHA1
 *
 * PURPOSE: Takes as an argument a char array and computes its SHA1 hash
 *
 * ARGUMENTS:
 *
 * ARGUMENT            TYPE            I/O     DESCRIPTION
 * --------            ----            ---     -----------
 * text                char*           I       the pointer to the char array containing the text to be hashed
 * text_byte_size      uint64_t*       I       the byte size of the char array to be hashed
 * hash                uint32_t*:      O       pointer to the uint32_t array where the resulting hash is to be stored
 *
 * RETURN VALUE : void
 *                                    
 *********************************************************************************************************************************/

void SHA1(char *text, uint64_t text_byte_size, uint32_t *hash)
{
    uint64_t text_byte_size_[1];
    text_byte_size_[0] = text_byte_size;
    SHA1_Concat(&text, 1, text_byte_size_, hash);
}

/*******************************************************************************************************************************
 *
 * FUNCTION NAME: SHA1_File
 *
 * PURPOSE: Takes as an argument a file name and computes the SHA1 hash of its content
 *
 * ARGUMENTS:
 *
 * ARGUMENT            TYPE            I/O     DESCRIPTION
 * --------            ----            ---     -----------
 * filename            char*           I       pointer to char array containing the file name
 * hash                uint32_t*:      O       pointer to the uint32_t array where the resulting hash is to be stored
 *
 * RETURN VALUE : int
 *
 *******************************************************************************************************************************/

int SHA1_File(char *filename, uint32_t *hash)
{
    int exit_status;                            /* exit status                          */
    FILE* fp;                                   /* pointer to the file to be hashed     */
    uint64_t file_byte_size;                    /* the size of the file in bytes        */
    unsigned char pad[BLOCK_SIZE + 9];          /* the pad                              */
    struct sha_word_pointer p;                  /* the word pointer                     */


    /* Open the file and determine its size */ 

    fp = fopen(filename, "rb");
    if (fp == NULL)
    {
        exit_status = EXIT_FAILURE;
        goto end;
    }
    fseek(fp, 0L, SEEK_END);
    file_byte_size = ftell(fp);
    rewind(fp);

    /* Initiate the word pointer */

    Set_Zero(&p);
    p.fp = fp;
    p.file_byte_size = file_byte_size;

    /* Set the pad */

    Set_64Byte_Pad(&p, pad, file_byte_size);
  
    /* Compute the hash */

    SHA1_Compute(&p, hash);

    /* Return exit status */

    exit_status = EXIT_SUCCESS;

    end:
    return exit_status;
} 

/*******************************************************************************************************************************
 *
 * FUNCTION NAME: HMAC_SHA1
 *
 * PURPOSE: Takes as an argument a string and a key and computes the corresponding HMAC-SHA1 digest
 *
 * ARGUMENTS:
 *
 * ARGUMENT            TYPE            I/O     DESCRIPTION
 * --------            ----            ---     -----------
 * key                 char*           I       the pointer to the char array containing the key
 * key_size            unsigned int    I       the key size in bytes
 * text                char*           I       the pointer to the char array containing the text to be digested with the key
 * text_size           uint64_t        I       the byte size of the char array containing the text
 * hash                uint32_t*:      O       pointer to the uint32_t array where the resulting digest is to be stored
 *
 * RETURN VALUE : void
 *
 *******************************************************************************************************************************/

void HMAC_SHA1(char *key, unsigned int key_size, char *text, uint64_t text_size, uint32_t *digest)
{
    int i;                                  /* internal counter variable                                    */
    char key0[BLOCK_SIZE];                  /* array to store the key adjusted to the block size            */
    char key0_xor_ipad[BLOCK_SIZE];         /* array to store the key0 with the ipad added to it            */
    char key0_xor_opad[BLOCK_SIZE];         /* array to store the key0 with the opad added to it            */
    uint32_t hash1[HASH_SIZE];              /* array to store the intermediate hash as integers             */
    char hash1_str[HASH_SIZE * WORD_SIZE];  /* array to store the intermediate hash as a string             */
    char *concat1[2];                       /* pointers to the first concatenation                          */
    char *concat2[2];                       /* pointers to the second concatenation                         */ 
    uint64_t concat1_byte_size[2];          /* the sizes of the strings forming the first concatenation     */
    uint64_t concat2_byte_size[2];          /* the sizes of the strings forming the second concatenation    */


    /* If the key is longer than the block size, hash the key and pad the result with zeros */

    if (key_size > BLOCK_SIZE)
    {
        uint32_t key_hash[HASH_SIZE];       /* array to store the hash of the key */
        SHA1(key, key_size, key_hash);

        for(i = 0; i < HASH_SIZE; i++)
            Conv_32Int_To_Word(key_hash[i], &key0[i * WORD_SIZE]);

        for(i = HASH_SIZE * WORD_SIZE; i < BLOCK_SIZE; i++)
            key0[i] = 0;
    }

    /* Otherwise pad the key with zeros */

    if (key_size <= BLOCK_SIZE)
    {
        for(i = 0; i < key_size; i++)
            key0[i] = key[i];

        for(i = key_size; i < BLOCK_SIZE; i++)
            key0[i] = 0;
    }

    /* Add the ipad to the key, concatenate it with the text and hash the result */ 

    for(i = 0; i < BLOCK_SIZE; i++)
        key0_xor_ipad[i] = key0[i] ^ 0x36;

    concat1[0] = key0_xor_ipad;
    concat1[1] = text;
    concat1_byte_size[0] = BLOCK_SIZE;
    concat1_byte_size[1] = text_size;

    SHA1_Concat(concat1, 2, concat1_byte_size, hash1);

    /* Convert the intermediate hash to a char array */

    for(i = 0; i < HASH_SIZE; i++)
        Conv_32Int_To_Word(hash1[i], &hash1_str[i * WORD_SIZE]);

    /* Add the opad to the key, concatenate it with the intermediate hash and hash the result */

    for(i = 0; i < BLOCK_SIZE; i++)
        key0_xor_opad[i] = key0[i] ^ 0x5c;

    concat2[0] = key0_xor_opad;
    concat2[1] = hash1_str;
    concat2_byte_size[0] = BLOCK_SIZE;
    concat2_byte_size[1] = HASH_SIZE * WORD_SIZE;

    SHA1_Concat(concat2, 2, concat2_byte_size, digest);
}


