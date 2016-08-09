/***************************************************************************************************************************************
 * FILE NAME: sha1.h
 *
 * Copyright (c)  2016 Anders Nordenfelt
 *
 * DATE: 2016-08-**
 *
 * CONTENT: Declares the functions and structs contained in the file sha1.c
 *
 **************************************************************************************************************************************/

#ifndef __SHA1__
#define __SHA1__

struct sha1_word_pointer;

void Move_Forward_One_Word(struct sha1_word_pointer *p);

void Conv_Int_To_Word(uint32_t i, char *a);

uint32_t f(unsigned int t, uint32_t x, uint32_t y, uint32_t z);

void Iterate_Hash(struct sha1_word_pointer *p, uint32_t *H);

void Sha1_Concat(char **strings, uint64_t nr_strings, uint64_t *strings_byte_len, uint32_t *hash);

void Sha1(char *strings_, uint64_t strings_byte_len_, uint32_t *hash);

void Hmac_Sha1(char *key, unsigned int key_len, char *text, uint64_t text_len, uint32_t *digest);

#endif
