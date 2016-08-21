/***************************************************************************************************************************************
 * FILE NAME: sha1.c
 *
 * Copyright (c)  2016 Anders Nordenfelt
 *
 * DATED: 2016-08-21
 *
 * CONTENT: Implements the SHA1 hash algorithm and its corresponding HMAC-SHA1 function in accordance with the 
 *          NIST specifications (FIPS PUB 180-4) and (FIPS PUB 198-1).
 *
 **************************************************************************************************************************************/
    
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "sha1.h"

#define TRUE 1
#define FALSE 0

#define BLOCK_SIZE 64       /* defines the size of a block in BYTES                                     */ 
#define WORD_SIZE 4         /* defines the size of a word in BYTES                                      */
#define HASH_SIZE 5         /* defines the size of the hash in number of 32-bit INTEGERS                */
#define DELIMITER 128       /* defines the unsigned char representation of the bit sequence '10000000'  */

/* MACROS */

#define Rot_Left(t, x) (((x) << t) | ((x) >> (32 - t)))
#define Ch(x, y, z) ((x & y) ^ (~x & z))
#define Parity(x, y, z) (x ^ y ^ z)
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

/************************************************************************************************************************************
 *
 * 	SECTION: DATA STRUCTURES AND ASSOCIATED METHODS
 *
 ***********************************************************************************************************************************/

/* The sha1_word_pointer defines a pointer type that acts as a virtual concatenation between the char arrays to be hashed 
   and the pad, or alternatively the file to be hashed and the pad */ 

struct sha1_word_pointer
{
    unsigned char word[WORD_SIZE];  /* contains the current word                                                        */
    unsigned int uint_rep;          /* provides an integer representation of the current word                           */
    uint64_t tot_byte_size;         /* the total size in bytes of the text including the pad                            */

    char **strings;                 /* pointer to the array of strings                                                  */
    uint64_t array_index;           /* index specifying in which string the pointer is positioned                       */
    uint64_t array_position;        /* index specifying where in the current string the pointer is positioned           */
    uint64_t nr_of_strings;         /* the number of strings in the concatenation                                       */
    uint64_t *strings_byte_size;    /* array containing the byte sizes of the strings in the concatenation              */

    FILE *fp;                       /* pointer to the file to be hashed, if any
                                       IMPORTANT! this pointer must be set to NULL if you want to hash strings instead  */
    uint64_t file_byte_size;        /* size in bytes of the file to be hashed                                           */
    uint64_t file_position;         /* position in the file                                                             */

    unsigned char *pad;             /* the pad                                                                          */
    unsigned int pad_byte_size;     /* pad length in bytes                                                              */
    unsigned int pad_position;      /* specifies the position in the pad                                                */
    int is_in_pad;                  /* specifies whether the pointer is in the pad or not                               */
};

/*-----------------------------------------------------------------------------------------------------------------------------*/

/* The function Move_Forward_One_Word advances the position of the word-pointer, loads a new word and saves its corresponding 
   integer representation. */


void Move_Forward_One_Word(struct sha1_word_pointer *p)
{
    int i;              /* internal counter variable */

    if (p->fp == NULL)  /* Perform the following for a string concatenation */
    {
        /* Fast track if the position is not close to the edge of the current string */
        if(p->array_index < p->nr_of_strings && p->array_position + 4 < p->strings_byte_size[p->array_index])
        {
            p->word[0] = (unsigned char) p->strings[p->array_index][p->array_position];
            p->word[1] = (unsigned char) p->strings[p->array_index][p->array_position + 1];
            p->word[2] = (unsigned char) p->strings[p->array_index][p->array_position + 2];
            p->word[3] = (unsigned char) p->strings[p->array_index][p->array_position + 3];
            p->array_position = p->array_position + 4;
        }
        else
        {
            i = 0;
            while (i < WORD_SIZE)
            {
                /* If the pointer is still within a string, load the word with a byte from the string and move forward one byte*/
                if (p->array_index < p->nr_of_strings && p->array_position < p->strings_byte_size[p->array_index])
                {
                    p->word[i] = (unsigned char) p->strings[p->array_index][p->array_position];
                    p->array_position++;
                    i++;
                }
                /* If the pointer is at the end of a string, jump to the next string */
                else if (p->array_position == p->strings_byte_size[p->array_index])
                {
                    p->array_index++;
                    p->array_position = 0;
                }
                /* If the pointer is in the pad, load the word with a byte from the pad and move forward one byte within the pad */
                else if (p->is_in_pad == TRUE && p->pad_position < p->pad_byte_size)
                {
                    p->word[i] = p->pad[p->pad_position];
                    p->pad_position++;
                    i++;
                }
                /* If there are no more strings, jump into the pad */
                else if (p->array_index == p->nr_of_strings)
                {
                    p->is_in_pad = TRUE;
                    p->pad_position = 0;
                }
                /* Else load a zero-byte to the word */
                else
                {
                    p->word[i] = 0;
                    i++;
                }
            }
        }
    }
    else /* Perform the following for a file */
    {
        /* Fast track if the position is not close to the pad */
        if(p->file_position + 4 < p->file_byte_size)
        {
            p->word[0] = (unsigned char) fgetc(p->fp);
            p->word[1] = (unsigned char) fgetc(p->fp);
            p->word[2] = (unsigned char) fgetc(p->fp);
            p->word[3] = (unsigned char) fgetc(p->fp);
            p->file_position = p->file_position + 4;
        }
        else
        {
            i = 0;
            while (i < WORD_SIZE)
            {
                /* If the pointer is still within the file, load the word with a byte from the file and move forward one byte */
                if ( p->file_position < p->file_byte_size)
                {
                    p->word[i] = (unsigned char) fgetc(p->fp);
                    p->file_position++;
                    i++;
                }
                /* If the pointer is in the pad, load the word with a byte from the pad and move forward one byte within the pad */
                else if (p->is_in_pad == TRUE && p->pad_position < p->pad_byte_size)
                {
                    p->word[i] = p->pad[p->pad_position];
                    p->pad_position++;
                    i++;
                }
                /* If we have reached the end of the file, jump into the pad */
                else if (p->is_in_pad == FALSE && p->file_position == p->file_byte_size)
                {
                    p->is_in_pad = TRUE;
                    p->pad_position = 0;
                }
                /* Else load a zero-byte to the word */
                else
                {
                    p->word[i] = 0;
                    i++;
                }
            }
        }
    }
    /* Convert the word to a 32-bit integer and store the result */
    p->uint_rep = ((uint32_t) p->word[0] << 24) | ((uint32_t) p->word[1] << 16) | ((uint32_t) p->word[2] << 8) | p->word[3];
}

/*------------------------------------------------------------------------------------------------------------------------------*/

/* The function Set_Zero sets all parameters in the word pointer to zero or NULL depending on their type */ 

void Set_Zero(struct sha1_word_pointer *p)
{
    p->array_index = 0;
    p->array_position = 0;
    p->strings = NULL;
    p->nr_of_strings = 0;
    p->strings_byte_size = NULL;
    p->pad = NULL;
    p->pad_position = 0;
    p->pad_byte_size = 0;
    p->is_in_pad = FALSE;
    p->fp = NULL;
    p->file_byte_size = 0;
    p->file_position = 0;
}

/*------------------------------------------------------------------------------------------------------------------------------*/

/* The function Set_Pad prepares and sets the pad, note that pointer with enough allocated memory for the pad must be provided  */

void Set_Pad(struct sha1_word_pointer *p, unsigned char *pad, uint64_t text_byte_size)
{
    int i;                                              /* internal counter variable                               */
    unsigned int nr_of_zeros;                           /* number of zero bytes in the pad                         */ 
    unsigned int pad_byte_size;                         /* the size of the pad                                     */
    uint64_t text_bit_size;                             /* the size in BITS of the text                            */

    /* Calculate the number of zeros in the pad and the pad size */

    nr_of_zeros = (BLOCK_SIZE - ((text_byte_size + 9) % BLOCK_SIZE)) % BLOCK_SIZE; 
    pad_byte_size = 9 + nr_of_zeros;

    /* Set the first byte in the pad equal to the delimiter 10000000b */

    pad[0] = DELIMITER;                                 

    /* Insert the zeros in the pad */

    for (i = 1; i <= nr_of_zeros; i++) 
        pad[i] = 0; 

    /* Insert an 8-byte rep. of the bit-size at the end of the pad */                                

    text_bit_size = 8*text_byte_size;      
    for (i = 0; i < 8; i++)
        pad[pad_byte_size - i - 1] = (text_bit_size >> i*8) & 255;  

    /* Put the pad and related data in the word pointer */  

    p->pad = pad;
    p->pad_position = 0;
    p->pad_byte_size = pad_byte_size;
    p->is_in_pad = FALSE;
    p->tot_byte_size = text_byte_size + pad_byte_size;
}

/***************************************************************************************************************************************
 * 
 *  SECTION: AUXILIARY FUNCTIONS
 *
 **************************************************************************************************************************************/

/* The function Conv_Int_To_Word takes a 32-bit integer argument and saves it as a four-byte char array 
   starting at the position specified by the pointer a.                                               */


void Conv_Int_To_Word(uint32_t i, char *a)
{
    a[0] = (i >> 24) & 255;
    a[1] = (i >> 16) & 255;
    a[2] = (i >> 8) & 255;
    a[3] = i & 255;
}


/***************************************************************************************************************************************
 * 
 *	SECTION: SHA1 IMPLEMENTATION
 *
 **************************************************************************************************************************************/


/* The function SHA1_Iterate_Hash implements the SHA1 hash iteration function. See the NIST documentation (FIPS PUB 180-4) for details. */


void SHA1_Iterate_Hash(struct sha1_word_pointer *p, uint32_t *H)
{
    const unsigned int K[] = {0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,   /* SHA1 constant vector */
                              0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
                              0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,  
                              0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
                              0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
                              0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 
                              0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
                              0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
                              0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
                              0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
                              0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
                              0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
                              0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
                              0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
                              0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
                              0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
                              0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
                              0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
                              0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
                              0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6};

    int i;                                    /* internal counter variable                  */
    uint32_t W[80], a, b, c, d, e, T;         /* integers variables used in the algorithm   */ 

    for (i = 0; i < 16; i++)
    {
        W[i] = p->uint_rep;                   /* Loads the variable W[i] with the integer representation of the current word */
        Move_Forward_One_Word(p);
    }

    for (i = 16; i < 80; i++)
        W[i] = Rot_Left(1, W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16]);

    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];

    for (i = 0; i < 20; i++)
    {
        T = Rot_Left(5, a) + Ch(b, c, d) + e + K[i] + W[i];
        e = d;
        d = c;
        c = Rot_Left(30, b);
        b = a;
        a = T;
    }

    for (i = 20; i < 40; i++)
    {
        T = Rot_Left(5, a) + Parity(b, c, d) + e + K[i] + W[i];
        e = d;
        d = c;
        c = Rot_Left(30, b);
        b = a;
        a = T;
    }

    for (i = 40; i < 60; i++)
    {
        T = Rot_Left(5, a) + Maj(b, c, d) + e + K[i] + W[i];
        e = d;
        d = c;
        c = Rot_Left(30, b);
        b = a;
        a = T;
    }

    for (i = 60; i < 80; i++)
    {
        T = Rot_Left(5, a) + Parity(b, c, d) + e + K[i] + W[i];
        e = d;
        d = c;
        c = Rot_Left(30, b);
        b = a;
        a = T;
    }

    H[0] = a + H[0];
    H[1] = b + H[1];
    H[2] = c + H[2];
    H[3] = d + H[3];
    H[4] = e + H[4];
}

/*------------------------------------------------------------------------------------------------------------------------------*/

void SHA1_Compute(struct sha1_word_pointer *p, uint32_t *hash)
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

    Move_Forward_One_Word(p);

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
 * PURPOSE: Takes as an argument a collection of char arrays, performs a virtual concatenation of these arrays in their given order,
 *          implements the SHA1 algorithm on the concatenated array and stores the resulting hash.
 *
 * ARGUMENTS:
 *
 * ARGUMENT            TYPE            I/O     DESCRIPTION
 * --------            ----            ---     -----------
 * strings             char**          I       the pointer to the char* array containing the pointers to the char arrays 
 *                                             to be hashed as a concatenation
 * nr_of_strings       uint64_t        I       the number of char arrays in the concatenation
 * strings_byte_size   uint64_t*       I       pointer to the uint64_t array containing the byte size of each char array 
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
    struct sha1_word_pointer p;                  /* the word pointer                                        */

    /* Initiate the word pointer */

    Set_Zero(&p);
    p.strings = strings;
    p.nr_of_strings = nr_of_strings;
    p.strings_byte_size = strings_byte_size;

    /* Calculate the total byte-size of the string concatenation and set the pad */

    concat_byte_size = 0;
    for (i = 0; i < nr_of_strings; i++)
        concat_byte_size = concat_byte_size + strings_byte_size[i];
    Set_Pad(&p, pad, concat_byte_size);

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
    struct sha1_word_pointer p;                 /* the word pointer                     */


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

    Set_Pad(&p, pad, file_byte_size);
  
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
            Conv_Int_To_Word(key_hash[i], &key0[i * WORD_SIZE]);

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
        Conv_Int_To_Word(hash1[i], &hash1_str[i * WORD_SIZE]);

    /* Add the opad to the key, concatenate it with the intermediate hash and hash the result */

    for(i = 0; i < BLOCK_SIZE; i++)
        key0_xor_opad[i] = key0[i] ^ 0x5c;

    concat2[0] = key0_xor_opad;
    concat2[1] = hash1_str;
    concat2_byte_size[0] = BLOCK_SIZE;
    concat2_byte_size[1] = HASH_SIZE * WORD_SIZE;

    SHA1_Concat(concat2, 2, concat2_byte_size, digest);
}


