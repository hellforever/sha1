/***************************************************************************************************************************************
 * FILE NAME: test_sha1.h
 *
 * Copyright (c)  2016 Anders Nordenfelt
 *
 * DATE: 2016-08-13
 *
 * CONTENT: Declares the tests contained in test_sha1.cpp of the functions Sha1_Concat, Sha1 and Hmac_Sha1 contained in sha1.h and sha1.c 
 *
 **************************************************************************************************************************************/

#ifndef __TEST_SHA1__
#define __TEST_SHA1__

#include <iostream>
#include <string>
#include <stdint.h>
#include "string.h"
#include "stdlib.h"
#include "time.h"

#include <cppunit/TextOutputter.h>
#include <cppunit/TextTestRunner.h>
#include <cppunit/TestResultCollector.h>
#include <cppunit/TestResult.h>
#include <cppunit/TestFailure.h>
#include <cppunit/TestCase.h>
#include <cppunit/TestSuite.h>
#include <cppunit/TestCaller.h>
#include <cppunit/TestRunner.h>

#include <cppunit/extensions/HelperMacros.h>

class Test_Sha1 : public CppUnit::TestCase {

public:

    CPPUNIT_TEST_SUITE( Test_Sha1 );
    CPPUNIT_TEST( Sha1_Concat_test1 );
    CPPUNIT_TEST( Sha1_Concat_test2 );
    CPPUNIT_TEST( Sha1_Concat_test3 );
    CPPUNIT_TEST( Sha1_test1 );
    CPPUNIT_TEST( Sha1_File_test1 );
    CPPUNIT_TEST( Hmac_Sha1_test1 );
	CPPUNIT_TEST( Hmac_Sha1_test2 );
	CPPUNIT_TEST( Hmac_Sha1_test3 );
    CPPUNIT_TEST_SUITE_END();

    void Sha1_Concat_test1();
    void Sha1_Concat_test2();
    void Sha1_Concat_test3();
	void Sha1_test1();
    void Sha1_File_test1();
    void Hmac_Sha1_test1();
    void Hmac_Sha1_test2();
	void Hmac_Sha1_test3();

};

#endif
