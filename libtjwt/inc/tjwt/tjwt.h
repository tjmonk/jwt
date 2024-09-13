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
#include <stdbool.h>

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

/*! JWT errors */
typedef enum _jwt_err
{
    /*! invalid TJWT object */
    TJWT_ERR_INVALID_OBJECT = 0,

    /*! memory allocation failure */
    TJWT_ERR_MEMORY_ALLOC = 1,

    /*! no token specified */
    TJWT_ERR_NO_TOKEN = 2,

    /*! invalid issuer */
    TJWT_ERR_INVALID_ISS = 3,

    /*! invalid issuer */
    TJWT_ERR_INVALID_SUB = 4,

    /*! invalid audience */
    TJWT_ERR_INVALID_AUD = 5,

    /*! token expired */
    TJWT_ERR_TOKEN_EXPIRED = 6,

    /*! current time before issued time */
    TJWT_ERR_TIME_BEFORE_IAT = 7,

    /*! current time before not-before time */
    TJWT_ERR_TIME_BEFORE_NBF = 8,

    /*! audience array is empty */
    TJWT_ERR_AUD_ARRAY_EMPTY = 9,

    /*! audience data type is invalid */
    TJWT_ERR_AUD_DATA_TYPE = 10,

    /*! too many audience values in claim */
    TJWT_ERR_AUD_TOO_MANY = 11,

    /*! failed to add audience claim */
    TJWT_ERR_AUD_ADD = 12,

    /*! key file not found */
    TJWT_ERR_KEY_FILE_NOT_FOUND = 13,

    /*! unsupported key file stat type */
    TJWT_ERR_KEY_FILE_STAT_TYPE = 14,

    /*! key file read error */
    TJWT_ERR_KEY_READ = 15,

    /*! unexpected key length */
    TJWT_ERR_KEY_LENGTH_UNEXPECTED = 16,

    /*! key file open failure */
    TJWT_ERR_KEY_OPEN = 17,

    /*! no key filename specified */
    TJWT_ERR_KEY_FILENAME = 18,

    /*! payload base64 decode error */
    TJWT_ERR_PAYLOAD_DECODE = 19,

    /*! signature base64 decode error */
    TJWT_ERR_SIGNATURE_DECODE = 20,

    /*! error constructing fully qualified keyfile name */
    TJWT_ERR_KEY_FQN = 21,

    /*! invalid section count in JWT token */
    TJWT_ERR_NUM_SECTIONS = 22,

    /*! invalid section length */
    TJWT_ERR_SECTION_LEN = 23,

    /*! Claim validation failed */
    TJWT_ERR_CLAIM_VALIDATION = 24,

    /*! invalid key type */
    TJWT_ERR_KEY_TYPE = 25,

    /*! signature verification failure */
    TJWT_ERR_SIGNATURE_VERIFY = 26,

    /*! invalid JWT type */
    TJWT_ERR_TYPE = 27,

    /*! unsupported JWT validation algorithm */
    TJWT_ERR_ALG = 28,

    /*! error parsing JWT header */
    TJWT_ERR_PARSE_HEADER = 29,

    /*! error parsing JWT payload */
    TJWT_ERR_PARSE_PAYLOAD = 30,

    /*! key id error */
    TJWT_ERR_KID = 31,

    /*! max error number */
    TJWT_ERR_MAX

} JWTErr;

/*==============================================================================
        Public function declarations
==============================================================================*/

TJWT *TJWT_Init();

int TJWT_ExpectKid( TJWT *jwt, char *kid );
int TJWT_ExpectAudience( TJWT *jwt, char *aud );
int TJWT_ExpectIssuer( TJWT *jwt, char *iss );
int TJWT_ExpectSubject( TJWT *jwt, char *sub );

int TJWT_Setkey( TJWT *jwt, char *key );
int TJWT_SetKeyFile( TJWT *jwt, char *filename );
int TJWT_SetKeyStore( TJWT *jwt, char *dirname );

int TJWT_SetClockSkew( TJWT *jwt, int skew );
int TJWT_Validate( TJWT *jwt, int64_t time, char *token );
JWTClaims *TJWT_GetClaims( TJWT *jwt );
int TJWT_PrintClaims( TJWT *jwt, int fd );

uint32_t TJWT_GetErrors( TJWT *jwt );
const char *TJWT_ErrorString( JWTErr err );
int TJWT_OutputErrors( TJWT *jwt, int fd );
int TJWT_PrintSections( TJWT *jwt, int fd );

bool TJWT_HasError( TJWT *jwt, JWTErr err );

int TJWT_Free( TJWT *jwt );

#endif
