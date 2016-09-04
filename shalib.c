/***************************************************************************************************************************************
 * FILE NAME: shalib.c
 *
 * Copyright (c)  2016 Anders Nordenfelt
 *
 * DATED: 2016-09-04
 *
 * CONTENT: Defines methods common to the SHA-algorithms
 *
 **************************************************************************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "shalib.h"

#define TRUE 1
#define FALSE 0 
#define DELIMITER 128


/***************************************************************************************************************************************/

/* The function Set_Zero sets all parameters in the word pointer to zero or NULL depending on their type */ 

void Set_Zero(struct sha_word_pointer *p)
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



/***************************************************************************************************************************************
 * 
 *  SECTION: 32-BIT METHODS
 *
 **************************************************************************************************************************************/

#define BLOCK_SIZE 64
#define WORD_SIZE 4



/* The function Conv_32Int_To_Word takes a 32-bit integer argument and saves it as a four-byte char array 
   starting at the position specified by the pointer a.                                               */

void Conv_32Int_To_Word(uint32_t i, char *a)
{
    a[0] = (i >> 24) & 255;
    a[1] = (i >> 16) & 255;
    a[2] = (i >> 8) & 255;
    a[3] = i & 255;
}

/* The function Conv_Word_To_32Int is the inverse of Conv_32Int_To_Word */

uint32_t Conv_Word_To_32Int(unsigned char *a)
{
    return a[0] << 24 |
           a[1] << 16 |
           a[2] << 8 |
           a[3];
}

/*----------------------------------------------------------------------------------------------------*/

/* The function Set_64Byte_Pad prepares and sets the pad for 64 byte blocks
   Note that pointer with enough allocated memory for the pad must be provided  */

void Set_64Byte_Pad(struct sha_word_pointer *p, unsigned char *pad, uint64_t text_byte_size)
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


/*------------------------------------------------------------------------------------------------------------------*/


void Load_String_32Int_Buffer(struct sha_word_pointer *p, uint32_t* W)
{
    int i;              /* internal counter variable */

    /* Fast track if the position is not close to the edge of the current string */
    if(p->array_index < p->nr_of_strings && p->array_position + BLOCK_SIZE < p->strings_byte_size[p->array_index])
    {
        for(i = 0; i < BLOCK_SIZE/WORD_SIZE; i++)
            W[i] = Conv_Word_To_32Int((unsigned char*) &p->strings[p->array_index][p->array_position + WORD_SIZE*i]);

        p->array_position = p->array_position + BLOCK_SIZE;
    }

    else
    {
        i = 0;

        do
        {
            /* If the pointer is in the pad, load the buffer with a byte from the pad */
            if (p->is_in_pad == TRUE && p->pad_position < p->pad_byte_size)
            {
                p->buffer[i] = p->pad[p->pad_position];
                p->pad_position++;
                i++;
            }
            /* If there are no more strings, jump into the pad */
            else if (p->array_index == p->nr_of_strings)
            {
                p->is_in_pad = TRUE;
                p->pad_position = 0;
            }
            /* If the pointer is at the end of a string, jump to the next string */
            else if (p->array_position == p->strings_byte_size[p->array_index])
            {
                p->array_index++;
                p->array_position = 0;
            }
            /* If the pointer is still within a string, load the buffer with a byte from the string */
            else if (p->array_index < p->nr_of_strings && p->array_position < p->strings_byte_size[p->array_index])
            {
                p->buffer[i] = (unsigned char) p->strings[p->array_index][p->array_position];
                p->array_position++;
                i++;
            }
            /* Else report error */
            else
            {
                printf("Error while loading sha buffer\n");
                exit(EXIT_FAILURE); 
            }
        }while (i < BLOCK_SIZE);

        /* Convert the buffer to 32-bit integers and store the result */
        for(i = 0; i < BLOCK_SIZE/WORD_SIZE; i++)
            W[i] = Conv_Word_To_32Int(&p->buffer[i*WORD_SIZE]);
    }
}

void Load_File_32Int_Buffer(struct sha_word_pointer *p, uint32_t* W)
{
    int i;              /* internal counter variable */

    /* Fast track if the position is not close to the pad */
    if(p->file_position + BLOCK_SIZE < p->file_byte_size)
        {
            for(i = 0; i < BLOCK_SIZE/WORD_SIZE; i++)
                W[i] = (unsigned char) fgetc(p->fp) << 24 |
                       (unsigned char) fgetc(p->fp) << 16 |
                       (unsigned char) fgetc(p->fp) << 8 |
                       (unsigned char) fgetc(p->fp);

            p->file_position = p->file_position + BLOCK_SIZE;
        }

    else
    {
        i = 0;

        do
        {
            /* If the pointer is in the pad, load the buffer with a byte from the pad */
            if (p->is_in_pad == TRUE && p->pad_position < p->pad_byte_size)
            {
                p->buffer[i] = p->pad[p->pad_position];
                p->pad_position++;
                i++;
            }
            /* If we have reached the end of the file, jump into the pad */
            else if (p->file_position == p->file_byte_size)
            {
                p->is_in_pad = TRUE;
                p->pad_position = 0;
            }
            /* If the pointer is still within the file, load the buffer with a byte from the file*/
            else if ( p->file_position < p->file_byte_size)
            {
                p->buffer[i] = (unsigned char) fgetc(p->fp);
                p->file_position++;
                i++;
            }
            /* Else report error */
            else
            {
                printf("Error while loading sha buffer\n");
                exit(EXIT_FAILURE); 
            }
        }while (i < BLOCK_SIZE);

        /* Convert the buffer to 32-bit integers and store the result */
        for(i = 0; i < BLOCK_SIZE/WORD_SIZE; i++)
            W[i] = Conv_Word_To_32Int(&p->buffer[i*WORD_SIZE]);
    }
}

/* The function Load_32Int_Buffer advances the position of the word-pointer one block and saves its corresponding 
   integer representation in the array W. */


void Load_32Int_Buffer(struct sha_word_pointer *p, uint32_t* W)
{
    if (p->fp == NULL)  
        Load_String_32Int_Buffer(p, W);

    else                
        Load_File_32Int_Buffer(p, W);
}

#undef BLOCK_SIZE
#undef WORD_SIZE




/***************************************************************************************************************************************
 * 
 *  SECTION: 64-BIT METHODS
 *
 **************************************************************************************************************************************/

#define BLOCK_SIZE 128
#define WORD_SIZE 8




/* The function Conv_64Int_To_Word takes an integer argument and saves it as a four-byte char array 
   starting at the position specified by the pointer a.                                         */

void Conv_64Int_To_Word(uint64_t i, char *a)
{
    a[0] = (i >> 56) & 255;
    a[1] = (i >> 48) & 255;
    a[2] = (i >> 40) & 255;
    a[3] = (i >> 32) & 255;
    a[4] = (i >> 24) & 255;
    a[5] = (i >> 16) & 255;
    a[6] = (i >> 8) & 255;
    a[7] = i & 255;
}

/* The function Conv_Word_To_64Int is the inverse of Conv_64Int_To_Word */

uint64_t Conv_Word_To_64Int(unsigned char *a)
{
    return (uint64_t) a[0] << 56 |
           (uint64_t) a[1] << 48 |
           (uint64_t) a[2] << 40 |
           (uint64_t) a[3] << 32 |
           (uint64_t) a[4] << 24 |
           (uint64_t) a[5] << 16 |
           (uint64_t) a[6] << 8 |
           (uint64_t) a[7];
}

/*-------------------------------------------------------------------------------------------------------------------*/

/* The function Set_128Byte_Pad sets the pad for 128 byte blocks
   Note that pointer with enough allocated memory for the pad must be provided  */

void Set_128Byte_Pad(struct sha_word_pointer *p, unsigned char *pad, uint64_t text_byte_size)
{
    int i;                                              /* internal counter variable                               */
    unsigned int nr_of_zeros;                           /* number of zero bytes in the pad                         */ 
    unsigned int pad_byte_size;                         /* the size of the pad                                     */
    uint64_t text_bit_size;                             /* the size in BITS of the text                            */

    nr_of_zeros = (BLOCK_SIZE - ((text_byte_size + 17) % BLOCK_SIZE)) % BLOCK_SIZE; 
    pad_byte_size = 17 + nr_of_zeros;

    /* Set the first byte in the pad equal to the delimiter 10000000b */

    pad[0] = DELIMITER;                                 

    /* Insert the zeros in the pad */

    for (i = 1; i <= nr_of_zeros + 8; i++) 
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

/*-------------------------------------------------------------------------------------------------------------------*/

void Load_String_64Int_Buffer(struct sha_word_pointer *p, uint64_t *W)
{
    int i;              /* internal counter variable */

    /* Fast track if the position is not close to the edge of the current string */
    if(p->array_index < p->nr_of_strings && p->array_position + BLOCK_SIZE < p->strings_byte_size[p->array_index])
    {
        for(i = 0; i < BLOCK_SIZE/WORD_SIZE; i++)
            W[i] = Conv_Word_To_64Int((unsigned char*) &p->strings[p->array_index][p->array_position + WORD_SIZE*i]);

        p->array_position = p->array_position + BLOCK_SIZE;
    }

    else
    {
        i = 0;

        do
        {
            /* If the pointer is in the pad, load the buffer with a byte from the pad */
            if (p->is_in_pad == TRUE && p->pad_position < p->pad_byte_size)
            {
                p->buffer[i] = p->pad[p->pad_position];
                p->pad_position++;
                i++;
            }
            /* If there are no more strings, jump into the pad */
            else if (p->array_index == p->nr_of_strings)
            {
                p->is_in_pad = TRUE;
                p->pad_position = 0;
            }
            /* If the pointer is at the end of a string, jump to the next string */
            else if (p->array_position == p->strings_byte_size[p->array_index])
            {
                p->array_index++;
                p->array_position = 0;
            }
            /* If the pointer is still within a string, load the buffer with a byte from the string */
            else if (p->array_index < p->nr_of_strings && p->array_position < p->strings_byte_size[p->array_index])
            {
                p->buffer[i] = (unsigned char) p->strings[p->array_index][p->array_position];
                p->array_position++;
                i++;
            }
            /* Else report error */
            else
            {
                printf("Error while loading sha buffer\n");
                exit(EXIT_FAILURE); 
            }
        }while (i < BLOCK_SIZE);

        /* Convert the buffer to 64-bit integers and store the result */
        for(i = 0; i < BLOCK_SIZE/WORD_SIZE; i++)
            W[i] = Conv_Word_To_64Int(&p->buffer[i*WORD_SIZE]);
    }
}

void Load_File_64Int_Buffer(struct sha_word_pointer *p, uint64_t *W)
{
    int i;              /* internal counter variable */

    /* Fast track if the position is not close to the pad */
    if(p->file_position + BLOCK_SIZE < p->file_byte_size)
        {
            for(i = 0; i < BLOCK_SIZE/WORD_SIZE; i++)
                W[i] = (uint64_t) fgetc(p->fp) << 56 |
                       (uint64_t) fgetc(p->fp) << 48 |
                       (uint64_t) fgetc(p->fp) << 40 |
                       (uint64_t) fgetc(p->fp) << 32 |
                       (uint64_t) fgetc(p->fp) << 24 |
                       (uint64_t) fgetc(p->fp) << 16 |
                       (uint64_t) fgetc(p->fp) << 8 |
                       (uint64_t) fgetc(p->fp);

            p->file_position = p->file_position + BLOCK_SIZE;
        }

    else
    {
        i = 0;

        do
        {
            /* If the pointer is in the pad, load the buffer with a byte from the pad */
            if (p->is_in_pad == TRUE && p->pad_position < p->pad_byte_size)
            {
                p->buffer[i] = p->pad[p->pad_position];
                p->pad_position++;
                i++;
            }
            /* If we have reached the end of the file, jump into the pad */
            else if (p->file_position == p->file_byte_size)
            {
                p->is_in_pad = TRUE;
                p->pad_position = 0;
            }
            /* If the pointer is still within the file, load the buffer with a byte from the file*/
            else if ( p->file_position < p->file_byte_size)
            {
                p->buffer[i] = (unsigned char) fgetc(p->fp);
                p->file_position++;
                i++;
            }
            /* Else report error */
            else
            {
                printf("Error while loading sha buffer\n");
                exit(EXIT_FAILURE); 
            }
        }while (i < BLOCK_SIZE);

        /* Convert the buffer to 64-bit integers and store the result */
        for(i = 0; i < BLOCK_SIZE/WORD_SIZE; i++)
            W[i] = Conv_Word_To_64Int(&p->buffer[i*WORD_SIZE]);
    }
}

/* The function Load_Buffer advances the position of the word-pointer one block and saves its corresponding 
   integer representation in the array W. */


void Load_64Int_Buffer(struct sha_word_pointer *p, uint64_t* W)
{
    if (p->fp == NULL)  
        Load_String_64Int_Buffer(p, W);

    else                
        Load_File_64Int_Buffer(p, W);
}

#undef BLOCK_SIZE
#undef WORD_SIZE


