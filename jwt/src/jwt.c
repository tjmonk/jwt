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
 * @defgroup jwtbin JWT Decoder
 * @brief JSON Web Token Decoder/Validator
 * @{
 */

/*============================================================================*/
/*!
@file jwt.c

    JSON Web Toke Decoder / Validator

    Utility application to decode and validate a JWT

*/
/*============================================================================*/

/*==============================================================================
        Includes
==============================================================================*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <getopt.h>
#include <time.h>
#include <tjwt/tjwt.h>

/*==============================================================================
        Private definitions
==============================================================================*/

/*! JWT decoder state */
typedef struct jwtState
{
    /*! verbose flag */
    bool verbose;

    /*! show program usage */
    bool usage;

    /*! issuer */
    char *iss;

    /*! audience */
    char *aud;

    /*! location of the key store */
    char *keystore;

    /*! JWT */
    char *token;

} JWTState;

#ifndef EOK
/*! zero means no error */
#define EOK 0
#endif

/*==============================================================================
        function declarations
==============================================================================*/
int main(int argc, char **argv);
static void usage( char *cmdname );
static int ProcessOptions( int argC, char *argV[], JWTState *pState );

/*==============================================================================
        Public function definitions
==============================================================================*/

/*============================================================================*/
/*  main                                                                      */
/*!
    Main entry point for the JWT Decoder / Validator

    The main function parses the command line options
    and executes the JWT decoding operation

    @param[in]
        argc
            number of arguments on the command line
            (including the command itself)

    @param[in]
        argv
            array of pointers to the command line arguments

    @return none

==============================================================================*/
int main(int argc, char **argv)
{
    JWTState state;
    TJWT *jwt = NULL;
    time_t now = time(NULL);
    int result = EINVAL;

    /* initialize the Session Manager State */
    memset( &state, 0, sizeof (JWTState));

    /* Process the command line options */
    ProcessOptions( argc, argv, &state );

    jwt = TJWT_Init();
    if ( jwt != NULL )
    {
        /* set the key store where we look for public validation keys */
        if ( state.keystore != NULL )
        {
            TJWT_SetKeyStore( jwt, state.keystore );
        }

        if ( state.iss != NULL )
        {
            /* expect a specific issuer */
            TJWT_ExpectIssuer( jwt, state.iss );
        }

        if ( state.aud != NULL )
        {
            /* expect a specific audience */
            TJWT_ExpectAudience( jwt, state.aud );
        }

        result = TJWT_Validate( jwt, now, state.token );

        if ( state.verbose == true )
        {
            TJWT_PrintSections( jwt, STDERR_FILENO );
            TJWT_PrintClaims( jwt, STDERR_FILENO );
            TJWT_OutputErrors( jwt, STDERR_FILENO );

            dprintf( STDOUT_FILENO,
                     ( result == EOK ) ? "Token is VALID!\n"
                                       : "Token is INVALID!\n");
        }

        TJWT_Free( jwt );
    }

    return ( result == EOK ) ? 1 : 0;
}

/*============================================================================*/
/*  usage                                                                     */
/*!
    Display the application usage

    The usage function dumps the application usage message to stderr.

    @param[in]
       cmdname
            pointer to the invoked command name

    @return none

==============================================================================*/
static void usage( char *cmdname )
{
    if( cmdname != NULL )
    {
        fprintf(stderr,
                "usage: %s [-v] [-h] [-i issuer] [-a audience] [-k keystore] "
                " [-t token]\n"
                " [-v] : verbose mode\n"
                " [-h] : display this help\n"
                " [-i issuer : "
                    "specifiy the issuer which must be present in the JWT\n"
                " [-a audience] : "
                    "specify the audience which must be present in the JWT\n"
                " [-k keystore] : "
                    "specify the location of the validation key store\n"
                " [-t token] : "
                    "specify the JSON Web Token to validate\n",
                cmdname );
    }
}

/*============================================================================*/
/*  ProcessOptions                                                            */
/*!
    Process the command line options

    The ProcessOptions function processes the command line options and
    populates the SessionMgrState object

    @param[in]
        argC
            number of arguments
            (including the command itself)

    @param[in]
        argv
            array of pointers to the command line arguments

    @param[in]
        pState
            pointer to the Session Manager state object

    @return none

==============================================================================*/
static int ProcessOptions( int argC, char *argV[], JWTState *pState )
{
    int c;
    int result = EINVAL;
    const char *options = "vht:a:k:i:";

    if( ( pState != NULL ) &&
        ( argV != NULL ) )
    {
        result = EOK;

        while( ( c = getopt( argC, argV, options ) ) != -1 )
        {
            switch( c )
            {
                case 'h':
                    usage( argV[0] );
                    exit( 1 );
                    break;

                case 'v':
                    pState->verbose = true;
                    break;

                case 'i':
                    /* issuer */
                    pState->iss = optarg;
                    break;

                case 'a':
                    /* audience */
                    pState->aud = optarg;
                    break;

                case 'k':
                    pState->keystore = optarg;
                    break;

                case 't':
                    pState->token = optarg;
                    break;

                default:
                    break;
            }
        }
    }

    return result;
}

/*! @}
 * end of jwt group */

