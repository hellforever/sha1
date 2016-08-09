/***************************************************************************************************************************************
 * FILE NAME: test_sha1.cpp
 *
 * Copyright (c)  2016 Anders Nordenfelt
 *
 * DATE: 2016-08-**
 *
 * CONTENT: Defines the tests of the functions Sha1_Concat, Sha1 and Hmac_Sha1 contained in the files sha1.h and sha1.c.
 *			At the time of completion of this file, the test vectors used were publically available on the following internet sites:
 *			http://www.di-mgt.com.au/sha_testvectors.html
 *			https://tools.ietf.org/html/rfc2202
 *
 **************************************************************************************************************************************/


#include "test_sha1.h"

/* File containing the functions to be tested. */
#include "sha1.h"



/** -------------------------------------------------------------------------- 

Test of Sha1_Concat with short text

text: 	"abc"

digest:	0x a9993e36, 4706816a, ba3e2571, 7850c26c, 9cd0d89d					*/

void Test_Sha1::Sha1_Concat_test1()
{

char msg1[] = {"ab"};
char msg2[] = {""};
char msg3[] = {"c"};
char *msg[] = {msg1, msg2, msg3};
uint64_t msg_len[] = {strlen(msg1), strlen(msg2), strlen(msg3)};

uint32_t digest[5];
	Sha1_Concat(msg, 3, msg_len, digest);

uint32_t reference[] = {0xa9993e36, 0x4706816a, 0xba3e2571, 0x7850c26c, 0x9cd0d89d};

for(int i = 0; i < 5; i++)
	CPPUNIT_ASSERT(digest[i] == reference[i]);

}

/** -------------------------------------------------------------------------- 

Test of Sha1_Concat with total text size shorter than the block-size of 64 bytes

text: 	"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"

digest:	0x 84983e44, 1c3bd26e, baae4aa1, f95129e5, e54670f1					*/

void Test_Sha1::Sha1_Concat_test2()
{

char msg1[] = {"abcdbcdecdefdefgefghfghig"};
char msg2[] = {"hijhijkijkljklmklmnlmnomnopnopq"};
char *msg[] = {msg1, msg2};
uint64_t msg_len[] = {strlen(msg1), strlen(msg2)};

uint32_t digest[5];
	Sha1_Concat(msg, 2, msg_len, digest);

uint32_t reference[] = {0x84983e44, 0x1c3bd26e, 0xbaae4aa1, 0xf95129e5, 0xe54670f1};

for(int i = 0; i < 5; i++)
	CPPUNIT_ASSERT(digest[i] == reference[i]);

}

/** -------------------------------------------------------------------------- 

Test of Sha1_Concat with total text size larger than the block-size of 64 bytes

text: 	"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"

digest:	0x a49b2446, a02c645b, f419f995, b6709125, 3a04a259					*/

void Test_Sha1::Sha1_Concat_test3()
{

char msg1[] = {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmgh"};
char msg2[] = {"ijklmnhijklmnoi"};
char msg3[] = {"jklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"};
char *msg[] = {msg1, msg2, msg3};
uint64_t msg_len[] = {strlen(msg1), strlen(msg2), strlen(msg3)};

uint32_t digest[5];
	Sha1_Concat(msg, 3, msg_len, digest);

uint32_t reference[] = {0xa49b2446, 0xa02c645b, 0xf419f995, 0xb6709125, 0x3a04a259};

for(int i = 0; i < 5; i++)
	CPPUNIT_ASSERT(digest[i] == reference[i]);

}

/** -------------------------------------------------------------------------- 

Test of Sha1 with long text

text: 	The letter 'a' repeated 1'000'000 times

digest:	0x 34aa973c, d4c4daa4, f61eeb2b, dbad2731, 6534016f					*/

void Test_Sha1::Sha1_test1()
{
int i;

char *msg = new char[1000000];
for (i = 0; i < 1000000; i++)
	msg[i] = 'a';

uint32_t digest[5];
	Sha1(msg, 1000000, digest);

uint32_t reference[] = {0x34aa973c, 0xd4c4daa4, 0xf61eeb2b, 0xdbad2731, 0x6534016f};

for(int i = 0; i < 5; i++)
	CPPUNIT_ASSERT(digest[i] == reference[i]);

delete msg;

}


/** --------------------------------------------------------------------------

Test of Hmac_Sha1 with both text and key shorter than the block-size of 64 bytes

text: 	"what do ya want for nothing?"

key:	"Jefe"

digest:	0x effcdf6a, e5eb2fa2, d27416d5, f184df9c, 259a7c79					*/

void Test_Sha1::Hmac_Sha1_test1()
{
int i;

char msg[] = {"what do ya want for nothing?"};
char key[] = {"Jefe"};

uint32_t digest[5];
	Hmac_Sha1(key, strlen(key), msg, strlen(msg), digest);

uint32_t reference[] = {0xeffcdf6a, 0xe5eb2fa2, 0xd27416d5, 0xf184df9c, 0x259a7c79};

for(i = 0; i < 5; i++)
	CPPUNIT_ASSERT(digest[i] == reference[i]);

}

/** -------------------------------------------------------------------------- 

Test of Hmac_Sha1 with both text and key longer than the block size of 64 bytes

text: 	"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"

key:	0xaa repeated 80 times

digest:	0x e8e99d0f, 45237d78, 6d6bbaa7, 965c7808, bbff1a91					*/

void Test_Sha1::Hmac_Sha1_test2()
{
int i;

char msg[] = {"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"};
char key[80];
for (i = 0; i < 80; i++)
	key[i] = 0xaa;

uint32_t digest[5];
	Hmac_Sha1(key, 80, msg, strlen(msg), digest);

uint32_t reference[] = {0xe8e99d0f, 0x45237d78, 0x6d6bbaa7, 0x965c7808, 0xbbff1a91};

for(i = 0; i < 5; i++)
	CPPUNIT_ASSERT(digest[i] == reference[i]);


}

/** -------------------------------------------------------------------------- 

Test of Hmac_Sha1 with both text and key defined by number sequences

text: 	0xcd repeated 50 times

key:	0x0102030405060708090a0b0c0d0e0f10111213141516171819

digest:	0x 4c9007f4 026250c6 bc8414f9 bf50c86c 2d7235da					*/

void Test_Sha1::Hmac_Sha1_test3()
{
int i;

char msg[50];
for (i = 0; i < 50; i++)
	msg[i] = 0xcd;
char key[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19};


uint32_t digest[5];
	Hmac_Sha1(key, 25, msg, 50, digest);

uint32_t reference[] = {0x4c9007f4, 0x026250c6, 0xbc8414f9, 0xbf50c86c, 0x2d7235da};

for(i = 0; i < 5; i++)
	CPPUNIT_ASSERT(digest[i] == reference[i]);


}

/** -------------------------------------------------------------------------- 

Main execution of the tests */

int main(int argc, char* argv[]) 
{
CppUnit::TextTestRunner runner;
runner.addTest(Test_Sha1::suite());
runner.run(std::string(""), false, true, false);
return 0;
}

