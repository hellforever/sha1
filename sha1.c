/***************************************************************************************************************************************
 * FILE NAME: sha1.c
 *
 * Copyright (c)  2016 Anders Nordenfelt
 *
 * DATED: 2016-08-**
 *
 * CONTENT: Implements the SHA1 hash algorithm and its corresponding HMAC-SHA1 function in accordance with the 
 * 			NIST specifications (FIPS PUB 180-4) and (FIPS PUB 198-1).
 *
 **************************************************************************************************************************************/
    
#include <stdint.h>
#include <stdlib.h>

#include "sha1.h"

#define TRUE 1
#define FALSE 0

#define BLOCK_SIZE 64
#define WORD_SIZE 4
#define HASH_SIZE 5
#define DELIMITER 128


/***************************************************************************************************************************************
 *
 * 	SECTION: DATA STRUCTURES AND ASSOCIATED METHODS
 *
 **************************************************************************************************************************************/

/** The sha1_word_pointer defines a pointer type that acts as a virtual concatenation between the char arrays to be hashed and the pad */ 

struct sha1_word_pointer
{

	uint64_t array_index;			/** index specifying in which string the pointer is positioned */
	uint64_t array_position;		/** index specifying where in the char array the pointer is positioned */
	unsigned char word[WORD_SIZE];	/** contains the current word */
	unsigned int uint_rep;			/** provides an integer representation for the current word */
	char **strings;					/** pointer to the string array */
	uint64_t nr_of_strings;			/** the number of strings in the string array */
	uint64_t *strings_byte_size;	/** array containing the byte lengths of the strings in the string array */
	unsigned char *pad;				/** the pad of the concatenation */
	unsigned int pad_byte_size;		/** pad length in bytes */
	unsigned int pad_position;		/** specifies the position in the pad */
	int is_in_pad;					/** specifies whether the pointer is in the pad or not */

};

/**------------------------------------------------------------------------------------------------------------------------------

The function Move_Forward_One_Word advances the position of the word-pointer, loads a new word and saves its  corresponding integer representation. 																												*/


void Move_Forward_One_Word(struct sha1_word_pointer *p)
{
int i = 0;		/** internal counter variable */

	while (i < WORD_SIZE)
	{
		/** If the pointer is still within a string, load the word with a byte from the string and move forward one byte*/
		if (p->array_position < p->strings_byte_size[p->array_index] && p->array_index < p->nr_of_strings)
		{
			p->word[i] = p->strings[p->array_index][p->array_position];
			p->array_position++;
			i++;
		}
		/** If the pointer is at the end of a string, jump to the next string */
		else if (p->array_position == p->strings_byte_size[p->array_index])
		{
			p->array_index++;
			p->array_position = 0;
		}
		/** If the pointer is in the pad, load the word with a byte from the pad and move forward one byte within the pad*/
		else if (p->is_in_pad == TRUE && p->pad_position < p->pad_byte_size)
		{
			p->word[i] = p->pad[p->pad_position];
			p->pad_position++;
			i++;
		}
		/** If there are no more strings, jump into the pad */
		else if (p->array_index == p->nr_of_strings)
		{
			p->is_in_pad = TRUE;
			p->pad_position = 0;
		}
		/** Else load a zero-byte to the word, this function is not responsible for a correct padding */
		else
		{
			p->word[i] = 0;
			i++;
		}
	}
	/** Convert the word to a 32-bit integer and store the result */
	p->uint_rep = (p->word[0] << 24) | (p->word[1] << 16) | (p->word[2] << 8) | p->word[3];
}

/***************************************************************************************************************************************
 * 
 * 	SECTION: AUXILIARY FUNCTIONS
 *
 ***************************************************************************************************************************************

The function Conv_Int_To_Word takes an integer argument and saves it as a four-byte char array starting at the position specified by the pointer a.																															*/


void Conv_Int_To_Word(uint32_t i, char *a)
{
	a[0] = (i >> 24) & 255;
	a[1] = (i >> 16) & 255;
	a[2] = (i >> 8) & 255;
	a[3] = i & 255;
}

/**------------------------------------------------------------------------------------------------------------------------------

The function Rot_Left takes an integer x as argument and performs a bitwise rotation t steps to the left.						*/


uint32_t Rot_Left(uint32_t t, uint32_t x)
{
return (x << t) | (x >> (32 - t));
}



/**------------------------------------------------------------------------------------------------------------------------------

The function f is used in the SHA1 hash iteration function. See the NIST documentation (FIPS PUB 180-4) for details.			*/


uint32_t f(unsigned int t, uint32_t x, uint32_t y, uint32_t z)
{

uint32_t result = 0;

	if (t <= 19)
	result = (x & y) ^ (~x & z);

	else if (t >= 20 && t <= 39)
	result = x ^ y ^ z;

	else if (t >= 40 && t <= 59)
	result = (x & y) ^ (x & z) ^ (y & z);

	else if (t >= 60 && t <= 79)
	result = x ^ y ^ z;

return result;

}

/***************************************************************************************************************************************
 * 
 *	SECTION: SHA1 IMPLEMENTATION
 *
 **************************************************************************************************************************************


The function Iterate_Hash implements the SHA1 hash iteration function. See the NIST documentation (FIPS PUB 180-4) for details.		*/


void Iterate_Hash(struct sha1_word_pointer *p, uint32_t *H)
{

const unsigned int K[] = {0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6};

int i;	/** internal counter variable */

uint32_t W[80];

	for (i = 0; i < 16; i++)
	{
		W[i] = p->uint_rep;	/** Loads the variable W[i] with the integer representation of the current word */
		Move_Forward_One_Word(p);
	}

	for (i = 16; i < 80; i++)
		W[i] = Rot_Left(1, W[i-3]^W[i-8]^W[i-14]^W[i-16]);

uint32_t a,b,c,d,e,T;
	
	a = H[0];
	b = H[1];
	c = H[2];
	d = H[3];
	e = H[4];

	for (i = 0; i < 80; i++)
	{
		T = Rot_Left(5,a) + f(i,b,c,d) + e + K[i] + W[i];
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

/**------------------------------------------------------------------------------------------------------------------------------

FUNCTION NAME: Sha1_Concat

PURPOSE: Takes as an argument a collection of char arrays, performs a virtual concatenation of these arrays in their given order,
		 implements the SHA1 algorithm on the concatenated array and stores the resulting hash.

ARGUMENTS:

char **strings 				:	the pointer to the char* array containing the pointers to the char arrays in the concatenation
uint64_t nr_of_strings 		:	the number of char arrays in the concatenation
uint64_t *strings_byte_size	:	pointer to the uint64_t array containing the byte length of each char array in order
uint32_t *hash				:	pointer to the uint32_t array where the resulting hash is to be stored

RETURNS : void																													*/

void Sha1_Concat(char **strings, uint64_t nr_of_strings, uint64_t *strings_byte_size, uint32_t *hash)
{

int i;										/** internal counter variable */
uint64_t concat_byte_size = 0;				/** variable to store the total byte-size of the string concatenation */

/** Calculate the total byte-size of the string concatenation */

	for (i = 0; i < nr_of_strings; i++)
		concat_byte_size = concat_byte_size + strings_byte_size[i];

/** Prepare and contruct the pad */

unsigned int nr_of_zeros;
	nr_of_zeros = (BLOCK_SIZE - ((concat_byte_size + 9) % BLOCK_SIZE)) % BLOCK_SIZE; /* Determine the number of zeros contained in the pad */
unsigned int pad_byte_size;
	pad_byte_size = 9 + nr_of_zeros;		/** Calculate the byte-size of the pad */

unsigned char pad[BLOCK_SIZE+9];
	pad[0] = DELIMITER;						/** Set the first byte in the pad equal to the delimiter 10000000b */

	for (i = 1; i <= nr_of_zeros; i++)	 
		pad[i] = 0;							/** Insert the zeros in the pad */

uint64_t concat_bit_size;
	concat_bit_size = 8*concat_byte_size;	/** Calculate the bit-size of the concatenation */

	for (i = 0; i < 8; i++)
		pad[pad_byte_size - i - 1] = (concat_bit_size >> i*8) & 255;	/** Insert an 8-byte rep. of the bit-size at the end of the pad */

/** Initiate the word pointer */

struct sha1_word_pointer p;
	p.array_index = 0;
	p.array_position = 0;
	p.strings = strings;
	p.nr_of_strings = nr_of_strings;
	p.strings_byte_size = strings_byte_size;
	p.pad = pad;
	p.pad_position = 0;
	p.pad_byte_size = pad_byte_size;
	p.is_in_pad = FALSE;

	Move_Forward_One_Word(&p);

/** Initiate the hash */

	uint32_t H[HASH_SIZE];

	H[0] = 0x67452301;
	H[1] = 0xefcdab89;
	H[2] = 0x98badcfe;
	H[3] = 0x10325476;
	H[4] = 0xc3d2e1f0;

/** Iterate the hash */

uint64_t tot_byte_size;
	tot_byte_size = concat_byte_size + pad_byte_size;
uint64_t N;
	N = tot_byte_size/BLOCK_SIZE;

	for (i = 0; i < N; i++)
		Iterate_Hash(&p, H);

/** Store final hash */

	for (i = 0; i < HASH_SIZE; i++)
		hash[i] = H[i];

}

/**------------------------------------------------------------------------------------------------------------------------------

FUNCTION NAME: Sha1

PURPOSE: Takes as an argument a char array, implements the SHA1 algorithm and stores the resulting hash

ARGUMENTS:

char *text 					:	the pointer to the char array containing the text to be hashed
uint64_t *text_byte_size_	:	the length of the char array to be hashed
uint32_t *hash				:	pointer to the uint32_t array where the resulting hash is to be stored

RETURNS : void																													*/


void Sha1(char *text, uint64_t text_byte_size_, uint32_t *hash)
{
	uint64_t text_byte_size[] = {text_byte_size_};
	Sha1_Concat(&text, 1, text_byte_size, hash);
}



/**------------------------------------------------------------------------------------------------------------------------------

FUNCTION NAME: Hmac_Sha1

PURPOSE: Takes as an argument a string and a key, implements the HMAC-SHA1 algorithm and stores the resulting digest

ARGUMENTS:

char *key	 				:	the pointer to the char array containing the key
unsigned int key_size		:	the key length in bytes
char *text					:	the pointer to the char array containing the text to be digested with the key
uint32_t *hash				:	pointer to the uint32_t array where the resulting digest is to be stored

RETURNS : void																													*/

void Hmac_Sha1(char *key, unsigned int key_size, char *text, uint64_t text_size, uint32_t *digest)
{

int i;						/** internal counter variable */
char key0[BLOCK_SIZE];

/** If the key is longer than the block size, hash the key and pad the result with zeros */

	if (key_size > BLOCK_SIZE)
	{
		uint32_t key_hash[HASH_SIZE];
		Sha1(key, key_size, key_hash);

		for(i = 0; i < HASH_SIZE; i++)
			Conv_Int_To_Word(key_hash[i], &key0[WORD_SIZE*i]);

		for(i = HASH_SIZE*WORD_SIZE; i < BLOCK_SIZE; i++)
			key0[i] = 0;
	}

/** Otherwise pad the key with zeros */

	if (key_size <= BLOCK_SIZE)
	{
		for(i = 0; i < key_size; i++)
			key0[i] = key[i];

		for(i = key_size; i < BLOCK_SIZE; i++)
			key0[i] = 0;
	}

/** Procedure to add the ipad to the key, concatenate it with the text and hash the result */ 

	char key0_xor_ipad[BLOCK_SIZE];		/** array to store the key0 with the ipad added to it */

	for(i = 0; i < BLOCK_SIZE; i++)
		key0_xor_ipad[i] = key0[i] ^ 0x36;

	char *concat1[] = {key0_xor_ipad, text};
	uint64_t concat1_byte_size[] = {BLOCK_SIZE, text_size};

	uint32_t hash1[HASH_SIZE];
	Sha1_Concat(concat1, 2, concat1_byte_size, hash1);


/** Convert the intermediate hash to a char array */

	char hash1_str[HASH_SIZE*WORD_SIZE];

	for(i = 0; i < HASH_SIZE; i++)
		Conv_Int_To_Word(hash1[i], &hash1_str[WORD_SIZE*i]);


/** Procedure to add the opad to the key, concatenate it with the intermediate hash and hash the result */

	char key0_xor_opad[BLOCK_SIZE];		/** array to store the key0 with the opad added to it */

	for(i = 0; i < BLOCK_SIZE; i++)
		key0_xor_opad[i] = key0[i] ^ 0x5c;

	char *concat2[] = {key0_xor_opad, hash1_str};
	uint64_t concat2_byte_size[] = {BLOCK_SIZE, HASH_SIZE*WORD_SIZE};

	Sha1_Concat(concat2, 2, concat2_byte_size, digest);

}

 
