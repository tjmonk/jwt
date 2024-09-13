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
 * @defgroup tjwt JSON Web Token
 * @brief JSON Web Token decoder
 * @{
 */

/*============================================================================*/
/*!
@file jwt.c

    JSON Web Token Decoder

    The JSON Web Token Decoder is a component used to decode JSON Web
    Tokens.

*/
/*============================================================================*/

/*==============================================================================
        Includes
==============================================================================*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <tjson/json.h>
#include <fcntl.h>
#include <errno.h>
#include "tjwt/tjwt.h"
#include "tjwt_obj.h"
#include "ssl.h"

/*==============================================================================
        Private definitions
==============================================================================*/

#ifndef EOK
/*! success response */
#define EOK ( 0 )
#endif

/*! JWT Header section number */
#define JWT_HEADER_SECTION ( 0 )

/*! JWT Payload section number */
#define JWT_PAYLOAD_SECTION ( 1 )

/*! JWT Signature section number */
#define JWT_SIGNATURE_SECTION ( 2 )

/*==============================================================================
        Private types
==============================================================================*/

/*! algorithm map */
typedef struct _alg_map
{
    /*! algorithm name */
    char *name;

    /*! hash function reference */
    const EVP_MD *(*sha)(void);

    /*! padding value */
    int padding;

    /*! verification function */
    int (*verify)(TJWT *);
} AlgMap;

/*==============================================================================
        Private function declarations
==============================================================================*/

static int split( const char *in, TJWT *jwt );
static int decode_jwt( TJWT *jwt );
static int load_key( TJWT *jwt );
static int read_key( TJWT *jwt, char *keyfile );

static char *get_key_name( TJWT *jwt );

static size_t b64url_decode( const uint8_t *in,
                             size_t len,
                             uint8_t *out,
                             const size_t outlen );

static int parse_header( TJWT *jwt );
static int select_algorithm( char *alg, TJWT *jwt );

static int parse_payload( TJWT *jwt );
static int process_aud( TJWT *jwt );
static int process_aud_var( TJWT *jwt, JVar *pVar );
static int process_aud_array( TJWT *jwt, JArray *pArray );

static int add_aud_claim( TJWT *jwt, JWTClaims *claims, char *aud, int max_aud);

static char *get_claim_string( TJWT *jwt, char *name );
static int get_claim_int( TJWT *jwt, char *name, int *n );

static int process_iss( TJWT *jwt );
static int process_sub( TJWT *jwt );
static int process_jti( TJWT *jwt );
static int process_nbf( TJWT *jwt );
static int process_exp( TJWT *jwt );
static int process_iat( TJWT *jwt );
static int process_kid( TJWT *jwt );

static int check_claims( TJWT *jwt );
static int check_kid( TJWT *jwt );
static int check_iss( TJWT *jwt );
static int check_sub( TJWT *jwt );
static int check_aud( TJWT *jwt );
static int check_time( TJWT *jwt );

/*==============================================================================
        Private file scoped variables
==============================================================================*/

/*! list of supported algorithms */
static const AlgMap algorithms[] = {
    { "RS512", EVP_sha512, RSA_PKCS1_PADDING, verify_rsa },
    { "RS384", EVP_sha384, RSA_PKCS1_PADDING, verify_rsa },
    { "RS256", EVP_sha256, RSA_PKCS1_PADDING, verify_rsa }
};

/*! array of TJWT Error descriptions */
static const char *TJWT_Errors[] =
{
    /* 0  */ "invalid TJWT object",
    /* 1  */ "memory allocation failure",
    /* 2  */ "no token specified",
    /* 3  */ "invalid issuer",
    /* 4  */ "invalid subject",
    /* 5  */ "invalid audience",
    /* 6  */ "token expired",
    /* 7  */ "clock time is before issued time",
    /* 8  */ "clock time is before not-before time",
    /* 9  */ "audience array empty",
    /* 10 */ "audience data type invalid",
    /* 11 */ "too many audiences specified",
    /* 12 */ "failed to add audience",
    /* 13 */ "key file not found",
    /* 14 */ "invalid key file type",
    /* 15 */ "failed to read key file",
    /* 16 */ "key length unexpected",
    /* 17 */ "failed to open key file",
    /* 18 */ "no key filename specified",
    /* 19 */ "payload decode error",
    /* 20 */ "signature decode error",
    /* 21 */ "failed to fully qualify key name",
    /* 22 */ "invalid number of JWT sections",
    /* 23 */ "JWT section length exceeded",
    /* 24 */ "claim validation failed",
    /* 25 */ "invalid key type",
    /* 26 */ "signature verification failed",
    /* 27 */ "invalid JWT type",
    /* 28 */ "unsupported validation algorithm",
    /* 29 */ "JWT header parse error",
    /* 30 */ "JWT payload parse error",
    /* 31 */ "JWT Key ID Error"
};

/*==============================================================================
        Public function definitions
==============================================================================*/

/*============================================================================*/
/*  TJWT_Init                                                                 */
/*!
    Initialize a TJWT object

    The TJWT_Init function creates a TJWT object to manage a JWT decode
    operation.  It allocates the TJWT object on the heap, which must be
    freed by the caller using the TJWT_Free function.

    @retval pointer to the TJWT object
    @retval NULL if the object could not be created.

==============================================================================*/
TJWT *TJWT_Init( void )
{
    return calloc( 1, sizeof( TJWT ) );
}

/*============================================================================*/
/*  TJWT_SetKeyStore                                                          */
/*!
    Set the key store reference

    The TJWT_SetKeyStore function sets the key store reference.
    This is the location where keys referenced via the JWT 'kid'
    attribute are stored.  This is the fully qualified path of a
    directory containing the key files.

    @param[in]
        jwt
            pointer to the TJWT object to update

    @param[in]
        dirname
            pointer to the directory name of the key store

    @retval EOK key store name updated
    @retval ENOMEM memory allocation failed
    @retval EINVAL invalid arguments

==============================================================================*/
int TJWT_SetKeyStore( TJWT *jwt, char *dirname )
{
    int result = EINVAL;

    if ( ( jwt != NULL ) &&
         ( dirname != NULL ) )
    {
        jwt->keystore = strdup( dirname );
        if ( jwt->keystore != NULL )
        {
            result = EOK;
        }
        else
        {
            jwt->error |= (1L << TJWT_ERR_MEMORY_ALLOC );
            result = ENOMEM;
        }
    }

    return result;
}

/*============================================================================*/
/*  TJWT_GetErrors                                                            */
/*!
    Get the error bitnap from the TJWT decoder

    The TJWT_GetErrors retrieves the error bitmap from the JWT decoding
    operation.  One or more error bits may be set.

    @param[in]
        jwt
            pointer to the TJWT object to query

    @retval 0 = no error
    @retval error bitfield

==============================================================================*/
uint32_t TJWT_GetErrors( TJWT *jwt )
{
    uint32_t error = 0;

    if ( jwt != NULL )
    {
        return jwt->error;
    }
    else
    {
        return 1L << TJWT_ERR_INVALID_OBJECT;
    }

    return error;
}

/*============================================================================*/
/*  TJWT_ExpectKid                                                            */
/*!
    Set the expected key id

    The TJWT_ExpectKid function sets the expected key id associated with
    the TJWT object.  If a JWT is received with a different (or non-existent)
    key id, then the key validation will fail.

    @param[in]
        jwt
            pointer to the TJWT object to update

    @param[in]
        kid
            pointer to the key id value to expect

    @retval EOK key id updated
    @retval ENOMEM memory allocation failed
    @retval EINVAL invalid arguments

==============================================================================*/
int TJWT_ExpectKid( TJWT *jwt, char *kid )
{
    int result = EINVAL;

    if ( ( jwt != NULL ) &&
         ( kid != NULL ) )
    {
        jwt->expected_kid = strdup( kid );
        if ( jwt->expected_kid != NULL )
        {
            result = EOK;
        }
        else
        {
            result = ENOMEM;
            jwt->error |= (1L << TJWT_ERR_MEMORY_ALLOC );
        }
    }

    return result;
}

/*============================================================================*/
/*  TJWT_SetKey                                                               */
/*!
    Set the key to use to validate the JWT signature

    The TJWT_SetKey function sets the key to use to validate the
    JWT signature.

    @param[in]
        jwt
            pointer to the TJWT object to update

    @param[in]
        key
            pointer to the key to use to validate the JWT signature

    @retval EOK public key updated
    @retval ENOMEM memory allocation failed
    @retval EINVAL invalid arguments

==============================================================================*/
int TJWT_SetKey( TJWT *jwt, char *key )
{
    int result = EINVAL;

    if ( ( jwt != NULL ) &&
         ( key != NULL ) )
    {
        jwt->key = strdup( key );
        if ( jwt->key != NULL )
        {
            result = EOK;
        }
        else
        {
            result = ENOMEM;
            jwt->error |= (1L << TJWT_ERR_MEMORY_ALLOC );
        }
    }

    return result;
}

/*============================================================================*/
/*  TJWT_SetKeyFile                                                           */
/*!
    Set the name of the key file to use to validate the JWT signature

    The TJWT_SetKeyFile function sets the name of the key file to use to
    validate the JWT signature.

    @param[in]
        jwt
            pointer to the TJWT object to update

    @param[in]
        filename
            pointer to the name of the key file to use to validate
            the JWT signature

    @retval EOK key file name updated
    @retval ENOMEM memory allocation failed
    @retval EINVAL invalid arguments

==============================================================================*/
int TJWT_SetKeyFile( TJWT *jwt, char *filename )
{
    int result = EINVAL;

    if ( ( jwt != NULL ) &&
         ( filename != NULL ) )
    {
        jwt->keyfile = strdup( filename );
        if ( jwt->keyfile != NULL )
        {
            result = EOK;
        }
        else
        {
            result = ENOMEM;
            jwt->error |= (1L << TJWT_ERR_MEMORY_ALLOC );
        }
    }

    return result;
}

/*============================================================================*/
/*  TJWT_SetClockSkew                                                         */
/*!
    Set the clock skew to allow when validating token time stamps

    The TJWT_SetClockSkew function sets the clock skew ( in seconds ) to
    allow when validating JWT timestamps.

    @param[in]
        jwt
            pointer to the TJWT object to update

    @param[in]
        clockskew
            clock skew in seconds

    @retval EOK clock skew updated
    @retval EINVAL invalid arguments

==============================================================================*/
int TJWT_SetClockSkew( TJWT *jwt, int clockskew )
{
    int result = EINVAL;

    if ( jwt != NULL )
    {
        jwt->clockskew = clockskew;
        result = EOK;
    }

    return result;
}

/*============================================================================*/
/*  TJWT_ExpectAudience                                                       */
/*!
    Set the expected key audience

    The TJWT_ExpectAudience function sets the expected audience associated with
    the TJWT object.  If a JWT is received with a different (or non-existent)
    audience, then the key validation will fail.

    @param[in]
        jwt
            pointer to the TJWT object to update

    @param[in]
        aud
            pointer to the audience value to expect

    @retval EOK audience updated
    @retval ENOMEM memory allocation failed
    @retval EINVAL invalid arguments

==============================================================================*/
int TJWT_ExpectAudience( TJWT *jwt, char *aud )
{
    int result = EINVAL;

    if ( ( jwt != NULL ) &&
         ( aud != NULL ) )
    {
        jwt->aud = strdup( aud );
        if ( jwt->aud != NULL )
        {
            result = EOK;
        }
        else
        {
            result = ENOMEM;
            jwt->error |= (1L << TJWT_ERR_MEMORY_ALLOC );
        }
    }

    return result;
}

/*============================================================================*/
/*  TJWT_ExpectSubject                                                        */
/*!
    Set the expected subject

    The TJWT_ExpectSubject function sets the expected subject associated with
    the TJWT object.  If a JWT is received with a different (or non-existent)
    subject, then the key validation will fail.

    @param[in]
        jwt
            pointer to the TJWT object to update

    @param[in]
        sub
            pointer to the subject value to expect

    @retval EOK audience updated
    @retval ENOMEM memory allocation failed
    @retval EINVAL invalid arguments

==============================================================================*/
int TJWT_ExpectSubject( TJWT *jwt, char *sub )
{
    int result = EINVAL;

    if ( ( jwt != NULL ) &&
         ( sub != NULL ) )
    {
        jwt->sub = strdup( sub );
        if ( jwt->sub != NULL )
        {
            result = EOK;
        }
        else
        {
            result = ENOMEM;
            jwt->error |= (1L << TJWT_ERR_MEMORY_ALLOC );
        }
    }

    return result;
}

/*============================================================================*/
/*  TJWT_ExpectIssuer                                                         */
/*!
    Set the expected issuer

    The TJWT_ExpectIssuer function sets the expected issuer associated with
    the TJWT object.  If a JWT is received with a different (or non-existent)
    issuer, then the key validation will fail.

    @param[in]
        jwt
            pointer to the TJWT object to update

    @param[in]
        iss
            pointer to the issuer value to expect

    @retval EOK issuer updated
    @retval ENOMEM memory allocation failed
    @retval EINVAL invalid arguments

==============================================================================*/
int TJWT_ExpectIssuer( TJWT *jwt, char *iss )
{
    int result = EINVAL;

    if ( ( jwt != NULL ) &&
         ( iss != NULL ) )
    {
        jwt->iss = strdup( iss );
        if ( jwt->iss != NULL )
        {
            result = EOK;
        }
        else
        {
            jwt->error |= (1L << TJWT_ERR_MEMORY_ALLOC );
            result = ENOMEM;
        }
    }

    return result;
}

/*============================================================================*/
/*  TJWT_Validate                                                             */
/*!
    Validate a JWT

    The TJWT_Validate function validates the specified JWT, it checks the
    following:

    - token signature
    - issuer
    - audience
    - key id
    - token time range

    If the token fails validation, authentication should fail and the
    associated request denied.

    @param[in]
        jwt
            pointer to the TJWT object to update

    @param[in]
        time
            current system time (POSIX seconds)

    @param[in]
        token
            JSON Web Token to be validated

    @retval EOK token is validated - access allowed
    @retval EACCES validation failed - access should be denied
    @retval EINVAL invalid arguments - access should be denied

==============================================================================*/
int TJWT_Validate( TJWT *jwt, int64_t timestamp, char *token )
{
    int result = EINVAL;
    bool rc;

    if ( jwt != NULL )
    {
        if ( token != NULL )
        {
            /* set the timestamp */
            jwt->timestamp = timestamp;

            rc = split( token, jwt ) ||
                parse_header( jwt ) ||
                load_key( jwt ) ||
                decode_jwt( jwt ) ||
                ( jwt->verify == NULL ) ||
                jwt->verify( jwt ) ||
                parse_payload( jwt ) ||
                check_claims( jwt ) ||
                check_kid( jwt );

            if ( rc == false )
            {
                result = EOK;
            }
        }
        else
        {
            jwt->error |= (1L << TJWT_ERR_NO_TOKEN );
        }
    }

    return result;
}

/*============================================================================*/
/*  check_claims                                                              */
/*!
    Check the expected claims against the received claims

    The check_claims function checks the expected claims against the
    received claims.  If any of the checks fail, then access will be
    denied.

    The claims checked are:

    - issuer
    - audience
    - subject
    - timestamp

    @param[in]
        jwt
            pointer to the TJWT object to validate

    @retval EOK claims are validated - access allowed
    @retval EACCES validation failed - access should be denied
    @retval EINVAL invalid arguments - access should be denied

==============================================================================*/
static int check_claims( TJWT *jwt )
{
    int result = EINVAL;
    int rc = 0;

    if ( jwt != NULL )
    {
        rc = check_iss( jwt ) ||
             check_sub( jwt ) ||
             check_aud( jwt ) ||
             check_time( jwt );

        if ( rc == 0 )
        {
            result = EOK;
        }
        else
        {
            result = EACCES;
            jwt->error |= ( 1L << TJWT_ERR_CLAIM_VALIDATION );
        }
    }

    return result;
}

/*============================================================================*/
/*  check_iss                                                                 */
/*!
    Check the expected issuer against the received claims

    The check_iss function checks the expected issuer against the
    received claims.  If no issuer is expected, we skip the check.
    If an issuer is expected and none was specified, then we deny access.
    If an issuer is expected and it does not exactly match the issuer
    received in the claims, then we deny access.

    @param[in]
        jwt
            pointer to the TJWT object to validate

    @retval EOK token is validated - access allowed
    @retval EACCES validation failed - access should be denied
    @retval EINVAL invalid arguments - access should be denied

==============================================================================*/
static int check_iss( TJWT *jwt )
{
    int result = EINVAL;

    if ( jwt != NULL )
    {
        /* see if we need to check the issuer */
        if ( jwt->iss != NULL )
        {
            /* we need to check the issuer */
            if ( jwt->claims.iss != NULL )
            {
                /* check the issuer matches the expected issuer */
                if ( strcmp( jwt->iss, jwt->claims.iss ) == 0 )
                {
                    result = EOK;
                }
                else
                {
                    /* issuer does not match expectation */
                    jwt->error |= ( 1L << TJWT_ERR_INVALID_ISS );
                    result = EACCES;
                }
            }
            else
            {
                /* we are expecting an issuer but none was specified */
                jwt->error |= ( 1L << TJWT_ERR_INVALID_ISS );
                result = EACCES;
            }
        }
        else
        {
            /* we don't care about the issuer */
            result = EOK;
        }
    }

    return result;
}

/*============================================================================*/
/*  check_kid                                                                 */
/*!
    Check the expected kid against the received kid

    The check_kid function checks the expected kid against the
    received kid.  If no kid is expected, we skip the check.
    If a kid is expected and none was specified, then we deny access.
    If a kid is expected and it does not exactly match the received kid
    then we deny access.

    @param[in]
        jwt
            pointer to the TJWT object to validate

    @retval EOK token is validated - access allowed
    @retval EACCES validation failed - access should be denied
    @retval EINVAL invalid arguments - access should be denied

==============================================================================*/
static int check_kid( TJWT *jwt )
{
    int result = EINVAL;

    if ( jwt != NULL )
    {
        /* see if we need to check the kid */
        if ( jwt->expected_kid != NULL )
        {
            /* we need to check the kid */
            if ( jwt->kid != NULL )
            {
                /* check the kid matches the expected kid */
                if ( strcmp( jwt->expected_kid, jwt->kid ) == 0 )
                {
                    result = EOK;
                }
                else
                {
                    /* kid does not match expectation */
                    jwt->error |= ( 1L << TJWT_ERR_KID );
                    result = EACCES;
                }
            }
            else
            {
                /* we are expecting a kid but none was specified */
                jwt->error |= ( 1L << TJWT_ERR_KID );
                result = EACCES;
            }
        }
        else
        {
            /* we don't care about the kid */
            result = EOK;
        }
    }

    return result;
}

/*============================================================================*/
/*  check_sub                                                                 */
/*!
    Check the expected subject against the received claims

    The check_sub function checks the expected subject against the
    received claims.  If no subject is expected, we skip the check.
    If a subject is expected and none was specified, then we deny access.
    If a subject is expected and it does not exactly match the subject
    received in the claims, then we deny access.

    @param[in]
        jwt
            pointer to the TJWT object to validate

    @retval EOK token is validated - access allowed
    @retval EACCES validation failed - access should be denied
    @retval EINVAL invalid arguments - access should be denied

==============================================================================*/
static int check_sub( TJWT *jwt )
{
    int result = EINVAL;

    if ( jwt != NULL )
    {
        /* see if we need to check the subject */
        if ( jwt->sub != NULL )
        {
            /* we need to check the subject */
            if ( jwt->claims.sub != NULL )
            {
                /* check the subject matches the expected subject */
                if ( strcmp( jwt->sub, jwt->claims.sub ) == 0 )
                {
                    result = EOK;
                }
                else
                {
                    /* subject does not match expectation */
                    jwt->error |= ( 1L << TJWT_ERR_INVALID_SUB );
                    result = EACCES;
                }
            }
            else
            {
                /* we are expecting a subject but none was specified */
                jwt->error |= ( 1L << TJWT_ERR_INVALID_SUB );
                result = EACCES;
            }
        }
        else
        {
            /* we don't care about the subject */
            result = EOK;
        }
    }

    return result;
}

/*============================================================================*/
/*  check_aud                                                                 */
/*!
    Check the expected audience against the received claims

    The check_aud function checks the expected audience against the
    received claims.  If no audience is expected, we skip the check.
    If an audience is expected and none was specified, then we deny access.
    If an audience is expected and it does not exactly match any of the
    names in the audience list received in the claims, then we deny access.

    @param[in]
        jwt
            pointer to the TJWT object to validate

    @retval EOK token is validated - access allowed
    @retval EACCES validation failed - access should be denied
    @retval EINVAL invalid arguments - access should be denied

==============================================================================*/
static int check_aud( TJWT *jwt )
{
    int result = EINVAL;
    int i;
    char *p;

    if ( jwt != NULL )
    {
        /* see if we need to check the audience */
        if ( jwt->aud != NULL )
        {
            /* we need to check the audience */
            if ( jwt->claims.aud != NULL )
            {
                /* assume we don't have access until we do */
                result = EACCES;

                /* check the audience matches the expected audience */
                for ( i = 0 ; i < jwt->claims.n_aud; i++ )
                {
                    p = jwt->claims.aud[i];
                    if ( p != NULL )
                    {
                        if ( strcmp( jwt->aud, p ) == 0 )
                        {
                            /* allow access */
                            result = EOK;
                            break;
                        }
                    }
                }

                if ( result != EOK )
                {
                    /* audience does not match expectation */
                    jwt->error |= ( 1L << TJWT_ERR_INVALID_AUD );
                }
            }
            else
            {
                /* we are expecting an audience but none was specified */
                jwt->error |= ( 1L << TJWT_ERR_INVALID_AUD );
                result = EACCES;
            }
        }
        else
        {
            /* we don't care about the audience */
            result = EOK;
        }
    }

    return result;
}

/*============================================================================*/
/*  check_time                                                                */
/*!
    Check the current time against the time range in the received claims

    The check_time function checks the current time against the
    time range in the received claims.

    If the current time is less than iat, or nbf then access will be denied.

    If the current time is greater than exp, then access will be denied.

    @param[in]
        jwt
            pointer to the TJWT object to validate

    @retval EOK token is validated - access allowed
    @retval EACCES validation failed - access should be denied
    @retval EINVAL invalid arguments - access should be denied

==============================================================================*/
static int check_time( TJWT *jwt )
{
    int result = EINVAL;
    int64_t timestamp;

    if ( jwt != NULL )
    {
        /* assume time is ok until it isn't */
        result = EOK;

        timestamp = jwt->timestamp;

        if ( jwt->claims.exp != 0 )
        {
            if ( timestamp > jwt->claims.exp + jwt->clockskew )
            {
                /* token has expired */
                jwt->error |= ( 1L << TJWT_ERR_TOKEN_EXPIRED );
                result = EACCES;
            }
        }

        if ( jwt->claims.iat != 0 )
        {
            if ( timestamp < jwt->claims.iat - jwt->clockskew )
            {
                /* timestamp is before token issued at time */
                jwt->error |= ( 1L << TJWT_ERR_TIME_BEFORE_IAT );
                result = EACCES;
            }
        }

        if ( jwt->claims.nbf != 0 )
        {
            if ( timestamp < jwt->claims.nbf - jwt->clockskew )
            {
                /* timestamp is before token not-before time */
                jwt->error |= ( 1L << TJWT_ERR_TIME_BEFORE_NBF );
                result = EACCES;
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  TJWT_GetClaims                                                            */
/*!
    Get the claims associated with the decoded JWT

    The TJWT_GetClaims function gets a pointer to the JWTClaims object
    associated with the specified JWT.  These claims should be considered
    read-only and must not be mutated.  The pointers in the claims object
    belong to the JWT lib and must not be cached for later use.

    @param[in]
        jwt
            pointer to the TJWT object to get the claims from

    @retval pointer to the JWT claims object
    @retval NULL invalid JWT

==============================================================================*/
JWTClaims *TJWT_GetClaims( TJWT *jwt )
{
    JWTClaims *claims = NULL;

    if ( jwt != NULL )
    {
        claims = &jwt->claims;
    }

    return claims;
}

/*============================================================================*/
/*  TJWT_PrintClaims                                                          */
/*!
    Print the claims associated with the JWT

    The TJWT_PrintClaims function pintts the claims associated with the
    JWT out to the file specified by the file descriptor.

    The following claims (if present) are printed:

    - token issuer
    - token subject
    - token audience
    - token identifier
    - token issued at timestamp
    - token non-before timestamp
    - token expiry timestamp

    @param[in]
        jwt
            pointer to the TJWT object to get the claims from

    @param[in]
        fd
            output file descriptor

    @retval EOK claims printed ok
    @retval EINVAL invalid arguments

==============================================================================*/
int TJWT_PrintClaims( TJWT *jwt, int fd )
{
    int result = EINVAL;
    int i;

    if ( ( jwt != NULL ) &&
         ( fd >= 0 ) )
    {
        if ( jwt->claims.iss != NULL )
        {
            dprintf( fd, "iss: %s\n", jwt->claims.iss );
        }

        if ( jwt->claims.sub != NULL )
        {
            dprintf( fd, "sub: %s\n", jwt->claims.sub );
        }

        if ( jwt->claims.jti != NULL )
        {
            dprintf( fd, "jti: %s\n", jwt->claims.jti );
        }

        if ( jwt->claims.aud != NULL )
        {
            for ( i = 0; i < jwt->claims.n_aud ; i++ )
            {
                dprintf( fd, "aud: %s\n", jwt->claims.aud[i] );
            }
        }

        dprintf( fd, "iat: %" PRId64 "\n", jwt->claims.iat );
        dprintf( fd, "exp: %" PRId64 "\n", jwt->claims.exp );
        dprintf( fd, "nbf: %" PRId64 "\n", jwt->claims.nbf );

        result = EOK;
    }

    return result;
}

/*============================================================================*/
/*  split                                                                     */
/*!
    Split an encoded JWT object into its separate parts

    The split function splits the JWT object into its separated parts
    by splitting on '.'

    @param[in]
        in
            pointer to the input string

    @param[in]
        argv
            array of pointers to the command line arguments

    @retval EOK message split successfully
    @retval EBADMSG not a properly formatted token
    @retval E2BIG too many sections in the JWT
    @retval EFBIG one or more sections was too large
    @retval EINVAL invalid arguments

==============================================================================*/
static int split( const char *in, TJWT *jwt )
{
    int i = 0;
    int j = 0;
    int section = 0;
    int result = EINVAL;
    char c;

    if ( ( in != NULL ) &&
         ( jwt != NULL ) )
    {
        /* assume everything is good until it is not */
        result = EOK;

        jwt->pToken = in;

        while ( ( c = in[i++] ) != 0 )
        {
            if ( c == '.' )
            {
                /* capture section length */
                jwt->sectionlen[section] = j;

                /* NUL terminate the current section */
                jwt->sections[section][j++] = 0;

                /* select the next section */
                section++;

                if ( section >= JWT_MAX_NUM_SECTIONS )
                {
                    /* number of sections is not supported */
                    jwt->error |= ( 1L << TJWT_ERR_NUM_SECTIONS );
                    result = E2BIG;
                    break;
                }

                /* reset the section output index */
                j = 0;
            }
            else
            {
                /* store the encoded byte in the output */
                jwt->sections[section][j++] = (uint8_t)c;
                if ( j >= JWT_MAX_SECTION_LEN )
                {
                    /* section is too big */
                    jwt->error |= ( 1L << TJWT_ERR_SECTION_LEN );
                    result = EFBIG;
                    break;
                }
            }
        }

        /* NUL terminate the last section and capture its length */
        if ( result == EOK )
        {
            jwt->sectionlen[section] = j;
            jwt->sections[section][j++] = 0;
            jwt->len = i;
            jwt->signedlen = jwt->sectionlen[JWT_HEADER_SECTION] +
                             jwt->sectionlen[JWT_PAYLOAD_SECTION] + 1;

        }

        /* check that we have all the sections we expect */
        if ( section < JWT_MAX_NUM_SECTIONS - 1 )
        {
            jwt->error |= ( 1L << TJWT_ERR_NUM_SECTIONS );
            result = EBADMSG;
        }
    }

    return result;
}

/*============================================================================*/
/*  TJWT_PrintSections                                                        */
/*!
    Print the sections of an encoded JWT object

    The PrintSections function prints out the sections of an encoded JWT
    object for debugging purposes.

    @param[in]
        jwt
            pointer to a JWT object that has split an input

    @retval EOK no errors
    @retval EINVAL invalid argument

==============================================================================*/
int TJWT_PrintSections( TJWT *jwt, int fd )
{
    int result = EINVAL;

    if ( ( jwt != NULL ) &&
         ( fd != -1 ) )
    {
        dprintf( fd, "header [%zu]: %s\n",
            jwt->sectionlen[JWT_HEADER_SECTION],
            jwt->sections[JWT_HEADER_SECTION] );

        dprintf( fd, "payload [%zu]: %s\n",
            jwt->sectionlen[JWT_PAYLOAD_SECTION],
            jwt->sections[JWT_PAYLOAD_SECTION] );

        dprintf( fd, "signature [%zu]: %s\n",
            jwt->sectionlen[JWT_SIGNATURE_SECTION],
            jwt->sections[JWT_SIGNATURE_SECTION] );

        result = EOK;
    }

    return result;
}

/*============================================================================*/
/*  decode_jwt                                                                */
/*!
    Decode a JWT object

    The decode_jwt function base64 decodes the header and payload
    sections of the JWT object.

    @param[in]
        in
            pointer to the JWT object to be decoded


    @retval EOK the JWT object was decoded successfully
    @retval EINVAL invalid input

==============================================================================*/
static int decode_jwt( TJWT *jwt )
{
    int result = EINVAL;
    size_t len;

    if ( jwt != NULL )
    {
        /* assume everything is ok until it is not */
        result = EOK;

        /* decode the payload */
        len = b64url_decode( jwt->sections[JWT_PAYLOAD_SECTION],
                             jwt->sectionlen[JWT_PAYLOAD_SECTION],
                             jwt->payload,
                             sizeof jwt->payload );
        jwt->payloadlen = len;
        if ( len == 0 )
        {
            jwt->error |= ( 1L << TJWT_ERR_PAYLOAD_DECODE );
            result = EINVAL;
        }

        len = b64url_decode( jwt->sections[JWT_SIGNATURE_SECTION],
                             jwt->sectionlen[JWT_SIGNATURE_SECTION],
                             jwt->sig,
                             sizeof jwt->sig );
        jwt->siglen = len;
        if ( len == 0 )
        {
            jwt->error |= ( 1L << TJWT_ERR_SIGNATURE_DECODE );
            result = EINVAL;
        }
    }

    return result;
}

/*============================================================================*/
/*  get_key_name                                                              */
/*!
    Get the fully qualified name of the validation key

    The get_key_name function gets the fully qualified name of the
    validation key file.  This is constructed from the key store path name
    and the key file name.

    The key file name is obtained from the user specified keyfile by default,
    and is overridden by the key id from the JWT 'kid' header.

    @param[in]
        in
            pointer to the TJWT object containing the key store path name
            and the key file name

    @retval pointer to the construct fully qualified key file name
    @retval NULL if the key name could not be constructed

==============================================================================*/
static char *get_key_name( TJWT *jwt )
{
    size_t len;
    char *keyfile = NULL;
    char *filename = NULL;
    int n = 0;

    if ( jwt != NULL )
    {
        if ( ( jwt->kid != NULL ) || ( jwt->keyfile != NULL ) )
        {
            if ( jwt->keyfile != NULL )
            {
                /* set the default key file name */
                filename = jwt->keyfile;
            }

            if ( jwt->kid != NULL )
            {
                /* override the key file name with the kid */
                filename = jwt->kid;
            }

            if ( jwt->keystore != NULL )
            {
                n = strlen( jwt->keystore );
            }

            if ( filename != NULL )
            {
                n += strlen( filename );
            }

            /* allow a / and and NUL terminator */
            n += 2;

            keyfile = calloc( 1, n );
            if ( keyfile != NULL )
            {
                if ( jwt->keystore != NULL )
                {
                    /* get the length of the key store string so we can
                    check the last character value */
                    len = strlen( jwt->keystore );
                    if ( jwt->keystore[len-1] == '/' )
                    {
                        /* construct the fully qualified key file name */
                        n = sprintf( keyfile,
                                    "%s%s",
                                    jwt->keystore,
                                    filename );
                    }
                    else
                    {
                        /* construct the fully qualified key file name */
                        n = sprintf( keyfile,
                                    "%s/%s",
                                    jwt->keystore,
                                    filename );
                    }

                    if ( n <= 0 )
                    {
                        jwt->error |= ( 1L << TJWT_ERR_KEY_FQN );
                        free( keyfile );
                        keyfile = NULL;
                    }
                }
                else
                {
                    keyfile = strdup( filename );
                    if ( keyfile == NULL )
                    {
                        jwt->error |= ( 1L << TJWT_ERR_MEMORY_ALLOC );
                    }
                }
            }
            else
            {
                jwt->error |= ( 1L << TJWT_ERR_MEMORY_ALLOC );
            }
        }
        else
        {
            jwt->error |= ( 1L << TJWT_ERR_KEY_FILENAME );
        }
    }

    return keyfile;
}

/*============================================================================*/
/*  load_key                                                                  */
/*!
    Load the key from a file

    The load_key function loads the specified JWT validation key
    into the JWT object if one has not already been loaded.

    @param[in]
        jwt
            pointer to the JWT object


    @retval EOK the key was loaded successfully
    @retval ENOENT cannot open key file
    @retval ENOTSUP unsupported file type
    @retval EINVAL invalid arguments

==============================================================================*/
static int load_key( TJWT *jwt )
{
    int result = EINVAL;
    struct stat sb;
    int rc;
    char *keyfile;

    if ( jwt != NULL )
    {
        /* only load the key if we don't already have one */
        if ( jwt->key == NULL )
        {
            /* get the name of the key */
            keyfile = get_key_name( jwt );
            if ( keyfile != NULL )
            {
                /* get the length of the file */
                rc = stat( keyfile, &sb );
                if ( rc != 0 )
                {
                    /* get error from stat function */
                    jwt->error |= ( 1L << TJWT_ERR_KEY_FILE_NOT_FOUND );
                    result = errno;
                }
                else
                {
                    /* check file type */
                    if ( sb.st_mode & S_IFREG )
                    {
                        /* allocate memory for the key */
                        jwt->key = calloc( 1, sb.st_size + 1 );
                        if ( jwt->key != NULL )
                        {
                            /* read the key from the file */
                            jwt->keylen = sb.st_size;
                            result = read_key( jwt, keyfile );
                        }
                        else
                        {
                            /* memory allocation failure */
                            jwt->error |= ( 1L << TJWT_ERR_MEMORY_ALLOC );
                            result = ENOMEM;
                        }
                    }
                    else
                    {
                        /* unsupported file type */
                        jwt->error |= ( 1L << TJWT_ERR_KEY_FILE_STAT_TYPE );
                        result = ENOTSUP;
                    }
                }

                free( keyfile );
                keyfile = NULL;
            }
            else
            {
                result = ENOENT;
            }
        }
        else
        {
            /* key already loaded */
            result = EOK;
        }
    }

    return result;
}

/*============================================================================*/
/*  read_key                                                                  */
/*!
    Read key data from a file

    The read_key function reads the specified JWT validation key
    into the JWT object.  The memory for the key must have been
    pre-allocated.

    @param[in]
        jwt
            pointer to the JWT object

    @param[in]
        keyfile
            pointer to the fully qualifed key file name

    @retval EOK the key was loaded successfully
    @retval EIO read length invalid
    @retval EINVAL invalid arguments

==============================================================================*/
static int read_key( TJWT *jwt, char *keyfile )
{
    int result = EINVAL;
    int fd;
    int n;

    if ( ( jwt != NULL ) &&
         ( keyfile != NULL ) &&
         ( jwt->key != NULL ) &&
         ( jwt->keylen > 0 ) )
    {
        /* open the key file */
        fd = open( keyfile, O_RDONLY );
        if ( fd != -1 )
        {
            /* read the key into the pre-allocated buffer */
            n = read( fd, jwt->key, jwt->keylen );
            if ( n == -1 )
            {
                /* get error from read function */
                jwt->error |= ( 1L << TJWT_ERR_KEY_READ );
                result = errno;
            }
            else if ( (size_t)n == jwt->keylen )
            {
                /* read was successful */
                /* NUL terminate the key */
                jwt->key[jwt->keylen] = 0;
                result = EOK;
            }
            else
            {
                /* unexpected read length */
                jwt->error |= ( 1L << TJWT_ERR_KEY_LENGTH_UNEXPECTED );
                result = EIO;
            }

            /* close the key file */
            close(fd);
        }
        else
        {
            /* get error from open function */
            jwt->error |= ( 1L << TJWT_ERR_KEY_OPEN );
            result = errno;
        }
    }

    return result;
}

/*============================================================================*/
/*  b64url_decode                                                             */
/*!
    base64 decode an input buffer using the base64url alphabet

    The b64url_decode function does a base64 decoding of the input
    buffer using the base64url alphabet and stores the decoded data
    in the output buffer.

    @param[in]
        in
            pointer to the base64url encoded data to be decoded

    @param[out]
        out
            pointer to the output buffer to write into

    @param[in]
        outlen
            size of the output buffer

    @retval number of bytes written to the output buffer
    @retval NULL if an error occurred

==============================================================================*/
static size_t b64url_decode( const uint8_t *in,
                             size_t len,
                             uint8_t *out,
                             const size_t outlen )
{
    uint32_t bits  = 0;
    int numbits  = 0;
    size_t padding = 0;
    size_t n       = 0;
    int8_t val;
    size_t i;

    static const int8_t map[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,63,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };

    if ( ( in != NULL ) &&
         ( out != NULL ) &&
         ( outlen > 0 ) )
    {
        /* count padding bytes */
        i = len - 1;
        while( ( in[i--] == '=' ) && ( padding <= 2 ) )
        {
            padding++;
        }

        if ( padding && ( ( len & 0x03 ) != 0 ) )
        {
            n = 0;
        }
        else
        {
            /* don't decode the padding bytes */
            len -= padding;

            for ( i = 0; ( i < len ) && ( n < outlen ); i++ )
            {
                /* get the 6-bit data */
                val = map[in[i]];
                if (val < 0)
                {
                    /* illegal character in input */
                    n = 0;
                    break;
                }

                /* append new bits to the LSB end of the collected bits */
                bits = (bits << 6) | val;

                /* increment the current bit count */
                numbits += 6;

                /* check if we have collected enough to emit an 8-bit value */
                if ( numbits >= 8 )
                {
                    /* emit an 8 bit value */
                    out[n++] = (uint8_t) ((bits >> (numbits - 8)) & 0xFF );

                    /* reduce the bit count by the number of bits emitted */
                    numbits -= 8;
                }
            }
        }
    }

    return ( i < len ) ? 0 : n;
}

/*============================================================================*/
/*  parse_header                                                              */
/*!
    parse the JWT header

    The parse_header function parses the JWT header and extracts tne
    alg, type, and kid attributes.

    @param[in]
        jwt
            pointer to the JWT object containing the header info

    @retval EOK header parsed ok
    @retval ENOTSUP unsuppored JWT object
    @retval EINVAL invalid argument

==============================================================================*/
static int parse_header( TJWT *jwt )
{
    int result = EINVAL;
    JNode *pHeader;
    char *alg;
    char *typ;
    bool match;
    size_t len;
    char *kid;

    if ( jwt != NULL )
    {
        result = EOK;

        /* decode the header */
        len = b64url_decode( jwt->sections[JWT_HEADER_SECTION],
                             jwt->sectionlen[JWT_HEADER_SECTION],
                             jwt->header,
                             sizeof jwt->header );
        jwt->headerlen = len;
        if ( len > 0 )
        {
            pHeader = JSON_ProcessBuffer( (char *)(jwt->header) );
            if ( pHeader != NULL )
            {
                /* get the (optional) key id from the header */
                kid = JSON_GetStr( pHeader, "kid" );
                if ( kid != NULL )
                {
                    jwt->kid = strdup( kid );
                    if ( jwt->kid == NULL )
                    {
                        jwt->error |= ( 1L << TJWT_ERR_MEMORY_ALLOC );
                        result = ENOMEM;
                    }
                }

                if ( result == EOK )
                {
                    typ = JSON_GetStr( pHeader, "typ" );
                    if ( typ != NULL )
                    {
                        match = ( typ[0] == 'j' || typ[0] == 'J' ) &&
                                ( typ[1] == 'w' || typ[1] == 'W') &&
                                ( typ[2] == 't' || typ[2] == 'T');
                        if ( match == true )
                        {
                            /* check the algorithm */
                            alg = JSON_GetStr( pHeader, "alg" );
                            result = select_algorithm( alg, jwt );
                        }
                        else
                        {
                            jwt->error |= ( 1L << TJWT_ERR_TYPE );
                        }
                    }
                    else
                    {
                        /* no 'typ' attribute found */
                        jwt->error |= ( 1L << TJWT_ERR_TYPE );
                        result = ENOTSUP;
                    }
                }

                /* free the JSON object */
                JSON_Free( pHeader );
            }
            else
            {
                /* cannot parse JSON header */
                jwt->error |= ( 1L << TJWT_ERR_PARSE_HEADER );
                result = ENOTSUP;
            }
        }
        else
        {
            jwt->error |= ( 1L << TJWT_ERR_PARSE_HEADER );
            result = ENOTSUP;
        }
    }

    return result;
}

/*============================================================================*/
/*  select_algorithm                                                          */
/*!
    select the appropriate decoding algorithm

    The select_algorithm function selects the appropriate JWT validation
    algorithm, given the algorithm name.  The following paramaters are
    selected:

    - SHA algorithm
    - padding
    - validation function

    @param[in]
        alg
            algorithm name

    @param[out]
        jwt
            pointer to the JWT object to be configured

    @retval EOK algorithm selected ok
    @retval ENOTSUP unsuppored algorithm
    @retval EINVAL invalid argument

==============================================================================*/
static int select_algorithm( char *alg, TJWT *jwt )
{
    int result = EINVAL;
    int i;
    int len = sizeof( algorithms ) / sizeof ( AlgMap );

    if ( ( alg != NULL ) && ( jwt != NULL ) )
    {
        result = ENOTSUP;

        for( i = 0; i < len ; i++ )
        {
            if ( strcmp( alg, algorithms[i].name ) == 0 )
            {
                jwt->sha = algorithms[i].sha();
                jwt->padding = algorithms[i].padding;
                jwt->verify = algorithms[i].verify;
                jwt->alg = algorithms[i].name;

                result = EOK;
                break;
            }
        }

        if ( result != EOK )
        {
            /* unsupported verification algorithm */
            jwt->error |= ( 1L << TJWT_ERR_ALG );
        }
    }

    return result;
}

/*============================================================================*/
/*  parse_payload                                                             */
/*!
    Parse the JWT payload and extract the claims

    The parse_payload function parses the JWT payload and extracts
    the claims for validation.

    @param[in]
        jwt
            pointer to the JWT object containing the claims payload

    @retval EOK payload parsed ok
    @retval EINVAL invalid argument

==============================================================================*/
static int parse_payload( TJWT *jwt )
{
    int result = EINVAL;

    if ( jwt != NULL )
    {
        jwt->pPayload = JSON_ProcessBuffer( (char *)(jwt->payload) );
        if ( ( jwt->pPayload != NULL ) &&
             ( jwt->pPayload->type == JSON_OBJECT ) )
        {
            process_aud( jwt );
            process_iss( jwt );
            process_sub( jwt );
            process_jti( jwt );
            process_nbf( jwt );
            process_exp( jwt );
            process_iat( jwt );
            process_kid( jwt );

            JSON_Free( jwt->pPayload );
            jwt->pPayload = NULL;

            result = EOK;
        }
        else
        {
            jwt->error |= ( 1L << TJWT_ERR_PARSE_PAYLOAD );
        }
    }

    return result;
}

/*============================================================================*/
/*  get_claim_int                                                             */
/*!
    Get an integer attribute from the processed JWT body

    The get_claim_int function searches the processed JWT body JSON for an
    integer value attribute with the specified name.

    @param[in]
        jwt
            pointer to the JWT object containing JWT body info

    @param[in]
        name
            pointer to the name of the attribute to retrieve

    @param[in,out]
        n
            pointer to a location to store the retrieved integer value

    @retval EOK the integer value was retrieved ok
    @retval ENOENT the attribute was not found
    @retval EINVAL invalid argument

==============================================================================*/
static int get_claim_int( TJWT *jwt, char *name, int *n )
{
    static int result;

    if ( ( jwt != NULL ) &&
         ( name != NULL ) &&
         ( n != NULL ) )
    {
        result = ( JSON_GetNum( jwt->pPayload, name, n ) == 0 ) ? EOK : ENOENT;
    }

    return result;
}

/*============================================================================*/
/*  get_claim_string                                                          */
/*!
    Get a string attribute from the processed JWT body

    The get_claim_string function searches the processed JWT body JSON for a
    string value attribute with the specified name.

    @param[in]
        jwt
            pointer to the JWT object containing the JWT body info

    @param[in]
        name
            pointer to the name of the attribute to retrieve

    @retval pointer to the retrieved string
    @retval NULL attribute could not be retrieved

==============================================================================*/
static char *get_claim_string( TJWT *jwt, char *name )
{
    char *result = NULL;

    if ( ( jwt != NULL ) &&
         ( name != NULL ) )
    {
        result = JSON_GetStr( jwt->pPayload, name );
    }

    return result;
}

/*============================================================================*/
/*  process_iss                                                               */
/*!
    Get the value of the 'iss' attribute from the JWT payload

    The process_iss function gets a copy of the 'iss' attribute from the
    body of the claim and stores it in the JWT's claim set.

    @param[in,out]
        jwt
            pointer to the JWT object containing the claims info to update

    @retval EOK the attribute string was successfully retrieved
    @retval ENOENT the attribute was not found
    @retval ENOMEM memory allocation failed
    @retval EINVAL invalid argument

==============================================================================*/
static int process_iss( TJWT *jwt )
{
    int result = EINVAL;
    char *iss;

    if ( jwt != NULL )
    {
        iss = get_claim_string( jwt, "iss" );
        if ( iss != NULL )
        {
            jwt->claims.iss = strdup( iss );
            if ( jwt->claims.iss != NULL )
            {
                result = EOK;
            }
            else
            {
                result = ENOMEM;
                jwt->error |= ( 1L << TJWT_ERR_MEMORY_ALLOC );
            }
        }
        else
        {
            result = ENOENT;
        }
    }

    return result;
}

/*============================================================================*/
/*  process_sub                                                               */
/*!
    Get the value of the 'sub' attribute from the JWT payload

    The process_sub function gets a copy of the 'sub' attribute from the
    body of the claim and stores it in the JWT's claim set.

    @param[in,out]
        jwt
            pointer to the JWT object containing the claims info to update

    @retval EOK the attribute string was successfully retrieved
    @retval ENOENT the attribute was not found
    @retval ENOMEM memory allocation failed
    @retval EINVAL invalid argument

==============================================================================*/
static int process_sub( TJWT *jwt )
{
    int result = EINVAL;
    char *sub;

    if ( jwt != NULL )
    {
        sub = get_claim_string( jwt, "sub" );
        if ( sub != NULL )
        {
            jwt->claims.sub = strdup( sub );
            if ( jwt->claims.sub != NULL )
            {
                result = EOK;
            }
            else
            {
                result = ENOMEM;
                jwt->error |= ( 1L << TJWT_ERR_MEMORY_ALLOC );
            }
        }
        else
        {
            result = ENOENT;
        }
    }

    return result;
}

/*============================================================================*/
/*  process_jti                                                               */
/*!
    Get the value of the 'jti' attribute from the JWT payload

    The process_jti function gets a copy of the 'jti' attribute from the
    body of the claim and stores it in the JWT's claim set.

    @param[in,out]
        jwt
            pointer to the JWT object containing the claims info to update

    @retval EOK the attribute string was successfully retrieved
    @retval ENOENT the attribute was not found
    @retval ENOMEM memory allocation failed
    @retval EINVAL invalid argument

==============================================================================*/
static int process_jti( TJWT *jwt )
{
    int result = EINVAL;
    char *jti;

    if ( jwt != NULL )
    {
        jti = get_claim_string( jwt, "jti" );
        if ( jti != NULL )
        {
            jwt->claims.jti = strdup( jti );
            if ( jwt->claims.jti != NULL )
            {
                result = EOK;
            }
            else
            {
                jwt->error |= ( 1L << TJWT_ERR_MEMORY_ALLOC );
                result = ENOMEM;
            }
        }
        else
        {
            result = ENOENT;
        }
    }

    return result;
}

/*============================================================================*/
/*  process_nbf                                                               */
/*!
    Get the value of the 'nbf' attribute from the JWT body JSON

    The process_nbf function gets the value of the integer 'nbf' attribute
    from the JWT body JSON and store it in the JWT's claim set object.

    @param[in,out]
        jwt
            pointer to the JWT object containing the claims info to be
            populated with the nbf value

    @retval EOK the integer attribute was successfully retrieved
    @retval ENOENT the integer attribute was not found
    @retval EINVAL invalid argument

==============================================================================*/
static int process_nbf( TJWT *jwt )
{
    int result = EINVAL;
    int n;

    if ( jwt != NULL )
    {
        result = get_claim_int( jwt, "nbf",  &n );
        if ( result == EOK )
        {
            jwt->claims.nbf = n;
        }
    }

    return result;
}

/*============================================================================*/
/*  process_exp                                                               */
/*!
    Get the value of the 'exp' attribute from the JWT body JSON

    The process_exp function gets the value of the integer 'exp' attribute
    from the JWT body JSON and store it in the JWT's claim set object.

    @param[in,out]
        jwt
            pointer to the JWT object containing the claims info to be
            populated with the exp value

    @retval EOK the integer attribute was successfully retrieved
    @retval ENOENT the integer attribute was not found
    @retval EINVAL invalid argument

==============================================================================*/
static int process_exp( TJWT *jwt )
{
    int result = EINVAL;
    int n;

    if ( jwt != NULL )
    {
        result = get_claim_int( jwt, "exp",  &n );
        if ( result == EOK )
        {
            jwt->claims.exp = n;
        }
    }

    return result;
}

/*============================================================================*/
/*  process_iat                                                               */
/*!
    Get the value of the 'iat' attribute from the JWT body JSON

    The process_iat function gets the value of the integer 'iat' attribute
    from the JWT body JSON and store it in the JWT's claim set object.

    @param[in,out]
        jwt
            pointer to the JWT object containing the claims info to be
            populated with the iat value

    @retval EOK the integer attribute was successfully retrieved
    @retval ENOENT the integer attribute was not found
    @retval EINVAL invalid argument

==============================================================================*/
static int process_iat( TJWT *jwt )
{
    int result = EINVAL;
    int n;

    if ( jwt != NULL )
    {
        result = get_claim_int( jwt, "iat",  &n );
        if ( result == EOK )
        {
            jwt->claims.iat = n;
        }
    }

    return result;
}

/*============================================================================*/
/*  process_kid                                                               */
/*!
    Get the value of the 'kid' attribute from the JWT body JSON

    The process_kid function gets the value of the string 'kid' attribute
    from the JWT body JSON and stores it in the JWT's claim set object.
    Normally a kid is passed in the header, but in this implementation
    was also allow it to be passed in the body since some JWT generators
    cannot specify a client provided kid in the header.

    @param[in,out]
        jwt
            pointer to the JWT object to be populated with the kid value

    @retval EOK the integer attribute was successfully retrieved
    @retval ENOENT the integer attribute was not found
    @retval EINVAL invalid argument

==============================================================================*/
static int process_kid( TJWT *jwt )
{
    int result = EINVAL;
    char *kid;

    if ( jwt != NULL )
    {
        kid = get_claim_string( jwt, "kid" );
        if ( kid != NULL )
        {
            jwt->kid = strdup( kid );
            if ( jwt->kid != NULL )
            {
                result = EOK;
            }
            else
            {
                result = ENOMEM;
                jwt->error |= ( 1L << TJWT_ERR_MEMORY_ALLOC );
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  process_aud                                                               */
/*!
    Get the value of the 'aud' attribute from the JWT body JSON

    The process_aud function gets the value of the string or array 'aud'
    attribute from the JWT body JSON and stores the aud values in the JWT's
    claim set object.

    @param[in,out]
        jwt
            pointer to the JWT object containing the claims info to be
            populated with the aud value(s)

    @retval EOK the aud string attribute was successfully retrieved
    @retval ENOENT the attribute was not found
    @retval ENOMEM memory allocation failed
    @retval EINVAL invalid argument

==============================================================================*/
static int process_aud( TJWT *jwt )
{
    int result = EINVAL;
    JObject *pObject;
    JNode *node;

    /* check if we have a valid payload object */
    if ( ( jwt != NULL ) &&
         ( jwt->pPayload != NULL ) &&
         ( jwt->pPayload->type == JSON_OBJECT ) )
    {
        pObject = (JObject *)(jwt->pPayload);

        /* check for 'aud' attribute */
        node = JSON_Attribute( pObject, "aud");
        if ( node != NULL )
        {
            switch ( node->type )
            {
                case JSON_VAR:
                    /* aud is a single value */
                    result = process_aud_var( jwt, (JVar *)node );
                    break;

                case JSON_ARRAY:
                    /* we have an array of 'aud' values */
                    result = process_aud_array( jwt, (JArray *)node );
                    break;

                default:
                    /* invalid aud data type */
                    jwt->error |= ( 1L << TJWT_ERR_AUD_DATA_TYPE );
                    result = ENOTSUP;
                    break;
            }
        }
        else
        {
            /* no 'aud' values found */
            result = EOK;
        }
    }

    return result;
}

/*============================================================================*/
/*  process_aud_var                                                           */
/*!
    Get the value of the 'aud' attribute from the JWT body JSON

    The process_aud_var function gets the value of the string 'aud'
    attribute from the JWT body JSON and stores the aud value in the JWT's
    claim set object.

    @param[in,out]
        jwt
            pointer to the JWT object containing the claims info to be
            populated with the aud value(s)

    @param[in]
        pVar
            pointer to the JVar object containing the aud value

    @retval EOK the aud string attribute was successfully retrieved
    @retval ENOMEM memory allocation failed
    @retval EINVAL invalid argument

==============================================================================*/
static int process_aud_var( TJWT *jwt, JVar *pVar )
{
    int result = EINVAL;

    if ( ( jwt != NULL ) &&
         ( pVar != NULL ) )
    {
        if ( ( pVar->node.type == JSON_VAR ) &&
             ( pVar->var.type == JVARTYPE_STR ) )
        {
            /* allocate memory for the 'aud' pointer */
            jwt->claims.aud = malloc( sizeof( char * ) );
            if ( jwt->claims.aud != NULL )
            {
                result = add_aud_claim( jwt,
                                        &jwt->claims,
                                        pVar->var.val.str,
                                        1 );
                if ( result != EOK )
                {
                    jwt->error |= ( 1L << TJWT_ERR_AUD_ADD );
                }
            }
            else
            {
                /* memory allocation failure */
                jwt->error |= (1L << TJWT_ERR_MEMORY_ALLOC );
                result = ENOMEM;
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  process_aud_array                                                         */
/*!
    Get the value of the 'aud' attribute from the JWT body JSON

    The process_aud_array function gets the values of the string 'aud'
    attributes from the JWT body JSON and stores the aud values in the JWT's
    claim set object.

    @param[in,out]
        jwt
            pointer to the JWT object containing the claims info to be
            populated with the aud value(s)

    @param[in]
        pArray
            pointer to the JArray array containing the aud values

    @retval EOK the aud string attributes were successfully retrieved
    @retval ENOENT no values in the aud array
    @retval ENOMEM memory allocation failed
    @retval EINVAL invalid argument

==============================================================================*/
static int process_aud_array( TJWT *jwt, JArray *pArray )
{
    int result = EINVAL;
    int n;
    int i;
    JNode *pNode;
    JVar *pVar;

    if ( ( jwt != NULL ) &&
         ( pArray != NULL ) &&
         ( pArray->node.type == JSON_ARRAY) )
    {
        /* get the number of 'aud' values */
        n = JSON_GetArraySize( pArray );
        if ( n > 0 )
        {
            /* allocate memory for the 'aud' pointers */
            jwt->claims.aud = malloc ( n * sizeof( char * ));
            if ( jwt->claims.aud != NULL )
            {
                for( i = 0; i < n ; i++ )
                {
                    pNode = JSON_Index( pArray, i );
                    if ( pNode != NULL )
                    {
                        if ( pNode->type == JSON_VAR )
                        {
                            pVar = (JVar *)pNode;
                            if ( pVar->var.type == JVARTYPE_STR )
                            {
                                result = add_aud_claim( jwt,
                                                        &jwt->claims,
                                                        pVar->var.val.str,
                                                        n );
                                if ( result != EOK )
                                {
                                    jwt->error |= ( 1L << TJWT_ERR_AUD_ADD );
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                jwt->error |= ( 1L << TJWT_ERR_MEMORY_ALLOC );
                result = ENOMEM;
            }
        }
        else
        {
            /* empty array */
            jwt->error |= ( 1L << TJWT_ERR_AUD_ARRAY_EMPTY );
            result = ENOENT;
        }

    }

    return result;
}

/*============================================================================*/
/*  add_aud_claim                                                             */
/*!
    Add an aud claim value to the claims set

    The add_aud_claim function adds an aud value to the list of
    aud values int he claims set.

    @param[in,out]
        claims
            pointer to the JWT claims object to be updated

    @param[in]
        aud
            pointe to an aud claim value

    @param[in]
        max_aud
            maximum size of the aud array

    @retval EOK the aud string was successfully added
    @retval E2BIG no more room in the aud string array
    @retval ENOMEM memory allocation failed
    @retval EINVAL invalid argument

==============================================================================*/
static int add_aud_claim( TJWT *jwt, JWTClaims *claims, char *aud, int max_aud )
{
    int result = EINVAL;
    int n;
    char *p;

    if ( ( jwt != NULL ) &&
         ( claims != NULL ) &&
         ( aud != NULL ) )
    {
        /* assume everything is ok until it isn't */
        result = EOK;

        /* get the current number of 'aud' values in the claims set */
        n = claims->n_aud;

        /* check if there is room for more */
        if ( n < max_aud )
        {
            /* allocate memory for the 'aud' claim */
            p = strdup( aud );
            if ( p != NULL )
            {
                /* store the 'aud' claim */
                n = claims->n_aud;
                claims->aud[n] = p;
                claims->n_aud = n + 1;
                result = EOK;
            }
            else
            {
                /* cannot allocate memory */
                jwt->error |= ( 1L << TJWT_ERR_MEMORY_ALLOC );
                result = ENOMEM;
            }
        }
        else
        {
            jwt->error |= ( 1L << TJWT_ERR_AUD_TOO_MANY );
            result = E2BIG;
        }
    }

    return result;
}

/*============================================================================*/
/*  TJWT_Free                                                                 */
/*!
    Deallocate the TJWT object

    The TJWT_Free function deallocates the specified TJWT object

    @param[in]
        jwt
            pointer to the JWT object to be released

    @retval EOK the TJWT object was released
    @retval EINVAL invalid argument

==============================================================================*/
int TJWT_Free( TJWT *jwt )
{
    int result = EINVAL;
    int i;

    if ( jwt != NULL )
    {
        /* free aud claims */
        for ( i=0; i < jwt->claims.n_aud ; i++ )
        {
            if ( jwt->claims.aud != NULL )
            {
                if ( jwt->claims.aud[i] != NULL )
                {
                    free( jwt->claims.aud[i] );
                    jwt->claims.aud[i] = NULL;
                }

                free( jwt->claims.aud );
                jwt->claims.aud = NULL;
            }
        }

        if ( jwt->claims.iss != NULL )
        {
            free( jwt->claims.iss );
            jwt->claims.iss = NULL;
        }

        if ( jwt->claims.jti != NULL )
        {
            free( jwt->claims.jti );
            jwt->claims.jti = NULL;
        }

        if ( jwt->claims.sub != NULL )
        {
            free( jwt->claims.sub );
            jwt->claims.sub = NULL;
        }

        if ( jwt->keystore != NULL )
        {
            free( jwt->keystore );
            jwt->keystore = NULL;
        }

        if ( jwt->kid != NULL )
        {
            free( jwt->kid );
            jwt->kid = NULL;
        }

        if ( jwt->key != NULL )
        {
            free( jwt->key );
            jwt->key = NULL;
        }

        if ( jwt->aud != NULL )
        {
            free( jwt->aud );
            jwt->aud = NULL;
        }

        if ( jwt->iss != NULL )
        {
            free( jwt->iss );
            jwt->iss = NULL;
        }

        if ( jwt->sub != NULL )
        {
            free( jwt->sub );
            jwt->sub = NULL;
        }

        if ( jwt->pPayload != NULL )
        {
            JSON_Free( jwt->pPayload );
            jwt->pPayload = NULL;
        }

        /* clear the JWT object ready for re-use */
        memset( jwt, 0, sizeof( TJWT ) );

        /* deallocate the JWT object */
        free( jwt );

        result = EOK;
    }

    return result;
}

/*============================================================================*/
/*  TJWT_ErrorString                                                          */
/*!
    Get the error string associated with the error index

    The TJWT_ErrorString function gets the error string associated
    with the error value;

    @param[in]
        err
            JWT error value

    @retval pointer to the error string associated with the error value
    @retval pointer to "unknown" if an invalid error string is requested

==============================================================================*/
const char *TJWT_ErrorString( JWTErr err )
{
    const char *errstr = "unknown";

    if ( ( err >= 0 ) && ( err < TJWT_ERR_MAX ) )
    {
        errstr = TJWT_Errors[err];
    }

    return errstr;
}

/*============================================================================*/
/*  TJWT_OutputErrors                                                         */
/*!
    Output the JWT errors

    The TJWT_OutputErrors function writes out all the detected JWT errors to the
    specified file descriptor.

    @param[in]
        jwt
            pointer to the JWT object containing the errors to output

    @param[in]
        fd
            output file descriptor

    @retval EOK the errors were output
    @retval EINVAL invalid argument

==============================================================================*/
int TJWT_OutputErrors( TJWT *jwt, int fd )
{
    uint32_t error = (1L << TJWT_ERR_INVALID_OBJECT );
    JWTErr err;
    int result = EINVAL;

    if ( jwt != NULL )
    {
        error = jwt->error;
        result = EOK;
    }

    for ( err = 0; err < TJWT_ERR_MAX; err++ )
    {
        if ( error & ( 1L << err ) )
        {
            dprintf( fd, "%s\n", TJWT_ErrorString(err) );
        }
    }

    return result;
}

/*============================================================================*/
/*  TJWT_HasError                                                             */
/*!
    Check if a JWT error is asserted

    The TJWT_HasError function checks if the specified JWT error is
    asserted (i.e the error has occurred).

    @param[in]
        jwt
            pointer to the JWT object containing the errors to check

    @param[in]
        err
            the specific error to check for

    @retval true - the error is present
    @retval false - the error is not present

==============================================================================*/
bool TJWT_HasError( TJWT *jwt, JWTErr err )
{
    bool result = false;

    if ( jwt != NULL )
    {
        result = ( jwt->error & ( 1L << err ) ) ? true : false;
    }

    return result;
}

/*! @}
 * end of tjwt group */
