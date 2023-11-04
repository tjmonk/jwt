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
#ifndef TJWT_H
#define TJWT_H

/*==============================================================================
        Includes
==============================================================================*/

#include <stdint.h>

/*==============================================================================
        Public definitions
==============================================================================*/

#ifndef EOK
/*! successful return */
#define EOK 0
#endif

/* opaque TJWT object */
typedef struct _jwt_obj TJWT;

/* the JWTClaims object contains all the JWT claims from the body of the JWT */
typedef struct _jwt_claims
{
    /*! pointer to the subject name */
    char *sub;

    /*! pointer to the issuer string */
    char *iss;

    /*! pointer to the JWT id */
    char *jti;

    /*! number of audience strings in the audience list */
    int n_aud;

    /*! pointer to an array of audience strings */
    char **aud;

    /*! expiration time */
    int64_t exp;

    /*! not-before time */
    int64_t nbf;

    /*! issued at time */
    int64_t iat;

} JWTClaims;

/*==============================================================================
        Public function declarations
==============================================================================*/

TJWT *TJWT_Init();

int TJWT_ExpectKid( TJWT *jwt, char *kid );
int TJWT_ExpectAudience( TJWT *jwt, char *aud );
int TJWT_ExpectIssuer( TJWT *jwt, char *iss );

int TJWT_SetPubkey( TJWT *jwt, char *pubkey );
int TJWT_SetPubKeyStore( TJWT *jwt, char *store );

int TJWT_SetClockSkew( TJWT *jwt, int skew );
int TJWT_Validate( TJWT *jwt, int64_t time, char *token );
JWTClaims *TJWT_GetClaims( TJWT *jwt );
int TJWT_PrintClaims( TJWT *jwt, int fd );

int TJWT_Free( TJWT *jwt );

#endif
