objects = test_sha1.o sha1.o shalib.o

tester	:	$(objects)
			g++ -o tester $(objects) -lcppunit 

sha1.o	:	sha1.c sha1.h
			g++ -c sha1.c

shalib.o	:shalib.c shalib.h
			g++ -c shalib.c

test_sha1.o	:	test_sha1.cpp test_sha1.h
				g++ -c test_sha1.cpp



