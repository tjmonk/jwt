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
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <tjwt/tjwt.h>

/*==============================================================================
        Private definitions
==============================================================================*/


/*==============================================================================
        Private types
==============================================================================*/

/*==============================================================================
        Private function declarations
==============================================================================*/

/*==============================================================================
        Private file scoped variables
==============================================================================*/

/*==============================================================================
        Public function definitions
==============================================================================*/

/*============================================================================*/
/*  main                                                                      */
/*!
    Main entry point for the jwt decoder

    The main function runs the jwt decoder

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
    TJWT *jwt = NULL;
    time_t now = 1698829980;

    if ( argc != 2 )
    {
        printf( "usage: %s <encoded jwt>\n", argv[0] );
        exit(1);
    }

    jwt = TJWT_Init();

    TJWT_SetKeyFile( jwt, "public.key" );
    TJWT_ExpectIssuer( jwt, "sunpower.com" );
    TJWT_ExpectSubject( jwt, "spwr_installer" );
    TJWT_ExpectAudience( jwt, "dev1" );

    if ( TJWT_Validate( jwt, now, argv[1] ) == EOK )
    {
        TJWT_PrintClaims( jwt, STDOUT_FILENO );

        printf("Validation successful!!! - Access Granted\n");
    }
    else
    {
        TJWT_OutputErrors( jwt, STDOUT_FILENO );
        printf("Validation failed - Access Denied\n");
    }

    TJWT_Free( jwt );

    exit( 0 );
}

/*! @}
 * end of jwt group */
