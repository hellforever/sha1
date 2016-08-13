##  SHA1 and HMAC-SHA1 implementation as an ANSI-C / C90 library  
##	in accordance with the NIST specifications (FIPS PUB 180-4) and (FIPS PUB 198-1).
##
##  Copyright (c)  2016  Anders Nordenfelt
##
## 	Files: sha1.h, sha1.c, test_sha1.h, test_sha1.cpp, makefile, README.md, testfile.txt 
##
##  The files are distributed under the terms of the GNU General Public License version 3, see <http://www.gnu.org/licenses/>.


## INSTALLATION

In order to install the executable test, enter the file directory containing the files and type

	$ make

	$ ./tester

This requires that you have installed the CPPUNIT package on your computer, which is freely available through the following terminal command

	$ sudo apt-get install libcppunit-dev



## DESIGN

The files sha1.c and sha1.h contain the library functions and can be compiled independently on any platform using a compiler supporting the ANSI C standard. The main user interface comes in the form of the three functions

	void Sha1(char *text, uint64_t text_size, uint32_t *hash)

    int Sha1_File(char *filename, uint32_t *hash)

	void Hmac_Sha1(char *key, unsigned int key_size, char *text, uint64_t text_size, uint32_t *digest)

The function Sha1 computes the hash of the character array pointed to by the variable 'text' and the user is required to pass as arguments also the size of the character array and a pointer where the resulting hash is to be stored. In the function Hmac_Sha1 it is also required to pass a key as a character array together with its size. The function Sha1_File takes as an argument instead a char array containing the name of a file to be hashed. If the file cannot be opened successfully the Sha1_File returns EXIT_FAILURE. Since it is generally expected that the hash functions should be able to digest messages of considerable size (2^64 bytes), the library functions do not make their own private copies of the character arrays but operates entirely with the pointers provided. The code is not optimized for speed but instead for portability, flexibility and compactness. If speed is a critical factor then other more specilized implementations might be better suited. If two or more character arrays need to be concatenated, for example in the implementation of Hmac_Sha1, functionality for this is provided by

	void Sha1_Concat(char **strings, uint64_t nr_of_strings, uint64_t *strings_byte_size, uint32_t *hash)

which takes as an argument an array of pointers to character arrays that are to be (virtually) concatenated in the order they appear. Here you must also pass the number of character arrays forming the concatenation together with an array containing the size of each character array in the order they appear. Examples of how these functions can be used are given in the file 

	test_sha1.cpp

The above file also contains a number of tests using publically available test vectors. 
