/***************************************************************************************************************************************
 * FILENAME: sha1.h
 *
 * Copyright (c) 2016 Anders Nordenfelt
 *
 * CONTENT: Function prototypes for the SHA1 C-library contained in sha1.c
 *
 **************************************************************************************************************************************/

#ifndef __SHA1__
#define __SHA1__

struct sha1_word_pointer;

void Load_Buffer(struct sha1_word_pointer *p, uint32_t *W);

void Set_Zero(struct sha1_word_pointer *p);

void Set_Pad(struct sha1_word_pointer *p, unsigned char *pad, uint64_t text_byte_size);

void Conv_Int_To_Word(uint32_t i, char *a);

void SHA1_Iterate_Hash(struct sha1_word_pointer *p, uint32_t *H);

void SHA1_Compute(struct sha1_word_pointer *p, uint32_t *hash);

void SHA1_Concat(char **strings, uint64_t nr_of_strings, uint64_t *strings_byte_len, uint32_t *hash);

void SHA1(char *text, uint64_t text_byte_size, uint32_t *hash);

int SHA1_File(char *filename, uint32_t *hash);

void HMAC_SHA1(char *key, unsigned int key_len, char *text, uint64_t text_len, uint32_t *digest);

#endif
