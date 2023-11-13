/*==============================================================================
MIT License

Copyright (c) 2023 Trevor Monk

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
==============================================================================*/

/*!
 * @defgroup jwttest JSON Web Token Tester
 * @brief JSON Web Token decoder/tester
 * @{
 */

/*============================================================================*/
/*!
@file jwttest.c

    JSON Web Token Decoder and Tester

    The JSON Web Token Decoder/Tester is a component used to test
    the libtjwt library

*/
/*============================================================================*/

/*==============================================================================
        Includes
==============================================================================*/

#include <errno.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <tjwt/tjwt.h>

/*==============================================================================
        Private definitions
==============================================================================*/


/*==============================================================================
        Private types
==============================================================================*/

typedef struct _test_case
{
    /*! test identifier */
    char *id;

    /* expected to validate? */
    bool valid;

    /* key store name */
    char *keystore;

    /* key file name */
    char *keyfilename;

    /*! expected audience */
    char *aud;

    /*! expected subject */
    char *sub;

    /*! JWT */
    char *token;

    /*! expected issuer */
    char *iss;

    /*! errors */
    uint32_t errors;

    /*! current time */
    int64_t time;

} JWTTestCase;

/*==============================================================================
        Private function declarations
==============================================================================*/

static int RunTest( const JWTTestCase *testcase );
static char *load_token( char *name );

/*==============================================================================
        Private file scoped variables
==============================================================================*/

/*! list of test cases to run */
static const JWTTestCase testcases[] = {

    {
        .id = "Test 1",
        .token = "token1",
        .keyfilename = "public.key",
        .iss = "sunpower.com",
        .sub = "spwr_installer",
        .aud = "dev1",
        .time = 1698829980,
        .valid = true,
        .errors = 0
    },
    {
        .id = "Test 2",
        .token = "no_token",
        .keyfilename = "public.key",
        .iss = "sunpower.com",
        .sub = "spwr_installer",
        .aud = "dev1",
        .time = 1698829980,
        .valid = false,
        .errors = (1L << TJWT_ERR_NO_TOKEN)
    },
    {
        .id = "Test 3",
        .token = "token1",
        .valid = false,
        .errors = (1L << TJWT_ERR_KEY_FILENAME)
    },
    {
        .id = "Test 4",
        .token = "token1",
        .keyfilename = "public.key",
        .iss = "spwr",
        .sub = "spwr_installer",
        .aud = "dev1",
        .time = 1698829980,
        .valid = false,
        .errors = (1L << TJWT_ERR_INVALID_ISS) |
                  (1L << TJWT_ERR_CLAIM_VALIDATION)
    },
    {
        .id = "Test 5",
        .token = "token1",
        .keyfilename = "public.key",
        .sub = "installer",
        .aud = "dev1",
        .time = 1698829980,
        .valid = false,
        .errors = (1L << TJWT_ERR_INVALID_SUB) |
                  (1L << TJWT_ERR_CLAIM_VALIDATION)
    },
    {
        .id = "Test 6",
        .token = "token1",
        .keyfilename = "public.key",
        .sub = "spwr_installer",
        .aud = "dev6",
        .time = 1698829980,
        .valid = false,
        .errors = (1L << TJWT_ERR_INVALID_AUD) |
                  (1L << TJWT_ERR_CLAIM_VALIDATION)
    },
    {
        .id = "Test 7",
        .token = "token1",
        .keyfilename = "public.key",
        .time = 1697729980,
        .valid = false,
        .errors = (1L << TJWT_ERR_TIME_BEFORE_IAT) |
                  (1L << TJWT_ERR_TIME_BEFORE_NBF) |
                  (1L << TJWT_ERR_CLAIM_VALIDATION)
    },
    {
        .id = "Test 8",
        .token = "token1",
        .keyfilename = "public.key",
        .time = 1698831024,
        .valid = false,
        .errors = (1L << TJWT_ERR_TOKEN_EXPIRED) |
                  (1L << TJWT_ERR_CLAIM_VALIDATION)
    }
};

/*==============================================================================
        Public function definitions
==============================================================================*/

/*============================================================================*/
/*  main                                                                      */
/*!
    Main entry point for the jwt test cases

    The main function runs the jwt test cases

    @param[in]
        argc
            number of arguments on the command line
            (including the command itself)

    @param[in]
        argv
            array of pointers to the command line arguments

    @return 0

==============================================================================*/
int main(int argc, char **argv)
{
    size_t i;
    size_t passed = 0;
    size_t failed = 0;
    size_t total = 0;

    (void)argc;
    (void)argv;

    total = sizeof(testcases) / sizeof( JWTTestCase );

    for( i = 0; i < total; i++ )
    {
        if ( RunTest( &testcases[i] ) == EOK )
        {
            passed++;
        }
        else
        {
            failed++;
        }
    }

    printf("%zu tests passed out of %zu\n", passed, total );
    printf("%zu tests failed\n", failed);

    if ( failed == 0 )
    {
        exit( 0 );
    }
    else
    {
        exit( 1 );
    }
}

/*============================================================================*/
/*  RunTest                                                                   */
/*!
    Run a single test

    The RunTest function runs a single test from the test cases list

    @param[in]
        testcase
            pointer to the testcase to run

    @return EOK test passed
    @retval EINVAL test failed

==============================================================================*/
static int RunTest( const JWTTestCase *testcase )
{
    TJWT *jwt;
    int result = EINVAL;
    int valid;
    uint32_t errors;
    char *token;

    if ( testcase != NULL )
    {
        jwt = TJWT_Init();
        if ( jwt != NULL )
        {
            if ( testcase->id != NULL )
            {
                dprintf(STDOUT_FILENO, "Test: %s ... ", testcase->id );
            }
            else
            {
                dprintf(STDOUT_FILENO, "Test: 'unnamed' ... ");
            }

            token = load_token( testcase->token );

            if ( testcase->keyfilename != NULL )
            {
                TJWT_SetKeyFile( jwt, testcase->keyfilename );
            }

            if ( testcase->iss != NULL )
            {
                TJWT_ExpectIssuer( jwt, testcase->iss );
            }

            if ( testcase->sub != NULL )
            {
                TJWT_ExpectSubject( jwt, testcase->sub );
            }

            if ( testcase->aud != NULL )
            {
                TJWT_ExpectAudience( jwt, testcase->aud );
            }

            if ( TJWT_Validate( jwt, testcase->time, token ) == EOK )
            {
                valid = true;
            }
            else
            {
                valid = false;
            }

            /* free the input token */
            free( token );
            token = NULL;

            errors = TJWT_GetErrors( jwt );

            if ( ( testcase->valid == valid ) &&
                 ( testcase->errors == errors ) )
            {
                dprintf( STDOUT_FILENO, "PASSED\n");
                result = EOK;
            }
            else
            {
                dprintf( STDOUT_FILENO, "FAILED\n");
                TJWT_PrintSections( jwt, STDERR_FILENO );
                TJWT_PrintClaims( jwt, STDERR_FILENO );
                TJWT_OutputErrors( jwt, STDERR_FILENO );
                result = EINVAL;
            }

            TJWT_Free( jwt );
        }
    }

    return result;
}

/*============================================================================*/
/*  load_token                                                                */
/*!
    Load a test token

    The load_token function loads a test token from a file on the disk
    The token is allocated on the heap and must be freed by the calling
    process.

    @param[in]
        name
            name of the token file

    @return pointer to the token data
    @retval NULL if the token could not be read

==============================================================================*/
static char *load_token( char *name )
{
    char *token = NULL;
    struct stat sb;
    int rc;
    int fd;
    size_t len;
    ssize_t n;

    if ( name != NULL )
    {
        /* get the length of the file */
        fd = open( name, O_RDONLY );
        if ( fd != -1 )
        {
            rc = fstat( fd, &sb );
            if ( rc == 0 )
            {
                if ( sb.st_mode & S_IFREG )
                {
                    /* allocate memory for the key */
                    len = sb.st_size;
                    token = calloc( 1, len + 1 );
                    if ( token != NULL )
                    {
                        /* read the key into the pre-allocated buffer */
                        n = read( fd, token, len );
                        if ( (size_t)n != len )
                        {
                            free( token );
                            token = NULL;
                        }

                        /* close the token file */
                        close(fd);
                    }
                }
            }
        }
    }

    return token;
}

/*! @}
 * end of jwt group */
