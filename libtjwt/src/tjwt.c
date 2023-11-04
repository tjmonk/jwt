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

/*==============================================================================
        Private definitions
==============================================================================*/

#ifndef EOK
/*! success response */
#define EOK ( 0 )
#endif

#ifndef JWT_MAX_SECTION_LEN
/*! maximum length of each section of a JWT */
#define JWT_MAX_SECTION_LEN ( 1024 )
#endif

#ifndef JWT_MAX_NUM_SECTIONS
/*! maximum supported sections in a JWT */
#define JWT_MAX_NUM_SECTIONS ( 3 )
#endif

/*! JWT Header section number */
#define JWT_HEADER_SECTION ( 0 )

/*! JWT Payload section number */
#define JWT_PAYLOAD_SECTION ( 1 )

/*! JWT Signature section number */
#define JWT_SIGNATURE_SECTION ( 2 )

/*! max JWT header length */
#ifndef JWT_MAX_HEADER_LEN
#define JWT_MAX_HEADER_LEN ( 128 )
#endif

/*! max JWT payload length */
#ifndef JWT_MAX_PAYLOAD_LEN
#define JWT_MAX_PAYLOAD_LEN ( 256 )
#endif

/*! max JWT validation key length */
#ifndef JWT_MAX_KEY_LEN
#define JWT_MAX_KEY_LEN ( 1024 )
#endif

/*! max JWT signature length */
#ifndef JWT_MAX_SIG_LEN
#define JWT_MAX_SIG_LEN ( 1024 )
#endif

/*==============================================================================
        Private types
==============================================================================*/

/*! JWT Object */
typedef struct _jwt_obj
{
    /* JWT Verification Key filename */
    char *keyfile;

    /*! SHA algorithm */
    const EVP_MD *sha;

    /*! padding type */
    int padding;

    /*! pointer to the full encoded data input */
    const char *pToken;

    /*! length of the full encoded jwt object */
    size_t len;

    /*! length of the signed part of the JWT object */
    size_t signedlen;

    /*! sections of a split JSON Web Token */
    uint8_t sections[JWT_MAX_NUM_SECTIONS][JWT_MAX_SECTION_LEN];

    /*! stores the length of each encoded JWT section */
    size_t sectionlen[JWT_MAX_NUM_SECTIONS];

    /*! base64 decoded header */
    uint8_t header[JWT_MAX_HEADER_LEN];

    /*! decoded header length */
    size_t headerlen;

    /*! base64 decoded payload */
    uint8_t payload[JWT_MAX_PAYLOAD_LEN];

    /*! length of the decoded payload */
    size_t payloadlen;

    /*! base64 decoded signature */
    uint8_t sig[JWT_MAX_SIG_LEN];

    /*! length of the decoded signature */
    size_t siglen;

    /*! pointer to the validating key */
    char key[JWT_MAX_KEY_LEN];

    /*! length of the validation key */
    size_t keylen;

    /*! verification function */
    int (*verify)( struct _jwt_obj * );

    /*! verification algorithm name */
    char *alg;

    /*! pointer to the JSON payload */
    JNode *pPayload;

    /* pointer to the name of the public key store */
    char *pubkeystore;

    /*! pointer to the key ID string */
    char *kid;

    /*! pointer to the expected audience string */
    char *aud;

    /*! pointer to the expected issuer string */
    char *iss;

    /*! pointer to the public key string */
    char *pubkey;

    /*! JWT claims */
    JWTClaims claims;

    /*! clock skew */
    int clockskew;

} TJWT;

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
static int PrintSections( TJWT *jwt );
static int decode_jwt( TJWT *jwt );
static int verify_rsa( TJWT *jwt );
static int load_key( TJWT *jwt );

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

static int add_aud_claim( JWTClaims *claims, char *aud, int max_aud );

static char *get_claim_string( TJWT *jwt, char *name );
static int get_claim_int( TJWT *jwt, char *name, int *n );

static int process_iss( TJWT *jwt );
static int process_sub( TJWT *jwt );
static int process_jti( TJWT *jwt );
static int process_nbf( TJWT *jwt );
static int process_exp( TJWT *jwt );
static int process_iat( TJWT *jwt );

/*==============================================================================
        Private file scoped variables
==============================================================================*/

/*! list of supported algorithms */
static const AlgMap algorithms[] = {
    { "RS512", EVP_sha512, RSA_PKCS1_PADDING, verify_rsa },
    { "RS384", EVP_sha384, RSA_PKCS1_PADDING, verify_rsa },
    { "RS256", EVP_sha256, RSA_PKCS1_PADDING, verify_rsa }
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
/*  TJWT_SetPubKeyStore                                                       */
/*!
    Set the public key store reference

    The TJWT_SetPubKeyStore function sets the public key store reference.
    This is the location where public keys referenced via the JWT 'kid'
    attribute are stored.  This is the fully qualified path of a
    directory containing the public key files.

    @param[in]
        jwt
            pointer to the TJWT object to update

    @param[in]
        store
            pointer to the directory name of the public key store

    @retval EOK public key store name updated
    @retval ENOMEM memory allocation failed
    @retval EINVAL invalid arguments

==============================================================================*/
int TJWT_SetPubKeyStore( TJWT *jwt, char *store )
{
    int result = EINVAL;

    if ( ( jwt != NULL ) &&
         ( store != NULL ) )
    {
        jwt->pubkeystore = strdup( store );
        if ( jwt->pubkeystore != NULL )
        {
            result = EOK;
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
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
        jwt->kid = strdup( kid );
        result = ( jwt->kid != NULL ) ? EOK : ENOMEM;
    }

    return result;
}

/*============================================================================*/
/*  TJWT_SetPubkey                                                            */
/*!
    Set the public key to use to validate the JWT signature

    The TJWT_SetPubkey function sets the public key to use to validate the
    JWT signature.

    @param[in]
        jwt
            pointer to the TJWT object to update

    @param[in]
        pubkey
            pointer to the public key to use to validate the JWT signature

    @retval EOK public key updated
    @retval ENOMEM memory allocation failed
    @retval EINVAL invalid arguments

==============================================================================*/
int TJWT_SetPubkey( TJWT *jwt, char *pubkey )
{
    int result = EINVAL;

    if ( ( jwt != NULL ) &&
         ( pubkey != NULL ) )
    {
        jwt->pubkey = strdup( pubkey );
        result = ( jwt->kid != NULL ) ? EOK : ENOMEM;
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
        result = ( jwt->aud != NULL ) ? EOK : ENOMEM;
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
        jwt->aud = strdup( iss );
        result = ( jwt->iss != NULL ) ? EOK : ENOMEM;
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
int TJWT_Validate( TJWT *jwt, int64_t time, char *token )
{
    int result = EINVAL;

    (void)time;

    if ( ( jwt != NULL ) &&
         ( token != NULL ) )
    {
        jwt->keyfile = "public.key";

        result = load_key( jwt );
        if ( result == EOK )
        {
            result = split( token, jwt );
            if ( result == EOK )
            {
                result = PrintSections( jwt );
                if ( result == EOK )
                {
                    result = parse_header( jwt );
                    if ( result == EOK )
                    {
                        result = decode_jwt( jwt );
                        if ( result == EOK )
                        {
                            if ( jwt->verify != NULL )
                            {
                                result = jwt->verify( jwt );
                                if ( result == EOK )
                                {
                                    result = parse_payload( jwt );
                                }
                            }
                        }
                    }
                }
            }
        }

        if( result != EOK )
        {
            printf("result: %s\n", strerror(result));
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
            result = EBADMSG;
        }
    }

    return result;
}

/*============================================================================*/
/*  PrintSections                                                             */
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
static int PrintSections( TJWT *jwt )
{
    int result = EINVAL;

    if ( jwt != NULL )
    {
        printf( "header: %s\n", jwt->sections[JWT_HEADER_SECTION] );
        printf( "payload: %s\n", jwt->sections[JWT_PAYLOAD_SECTION] );
        printf( "signature: %s\n", jwt->sections[JWT_SIGNATURE_SECTION] );

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
            result = EINVAL;
        }

        len = b64url_decode( jwt->sections[JWT_SIGNATURE_SECTION],
                             jwt->sectionlen[JWT_SIGNATURE_SECTION],
                             jwt->sig,
                             sizeof jwt->sig );
        jwt->siglen = len;
        if ( len == 0 )
        {
            result = EINVAL;
        }
    }

    return result;
}

/*============================================================================*/
/*  load_key                                                                  */
/*!
    Load the key from a file

    The load_key function loads the specified JWT validation key
    into the JWT object.

    @param[in]
        jwt
            pointer to the JWT object


    @retval EOK the JWT object was decoded successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int load_key( TJWT *jwt )
{
    int result = EINVAL;
    struct stat sb;
    int rc;
    int fd;
    ssize_t n;

    if ( ( jwt != NULL ) &&
         ( jwt->keyfile != NULL ) )
    {
        rc = stat( jwt->keyfile, &sb );
        if ( rc != 0 )
        {
            result = errno;
        }
        else
        {
            if ( ( sb.st_mode & S_IFREG ) &&
                 ( sb.st_size < JWT_MAX_KEY_LEN ) )
            {
                fd = open( jwt->keyfile, O_RDONLY );
                if ( fd != -1 )
                {
                    n = read( fd, jwt->key, JWT_MAX_KEY_LEN );
                    if ( n < JWT_MAX_KEY_LEN )
                    {
                        jwt->keylen = n;
                        result = EOK;
                    }

                    close(fd);
                }
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  verify_rsa                                                                */
/*!
    RSA verification of the JWT

    The verify_rsa function verifies the JWT using RSA public key
    verification.

    @param[in]
        jwt
            pointer to the JWT object

    @retval EOK the JWT object was verified successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int verify_rsa( TJWT *jwt )
{
    int result = EINVAL;

    EVP_MD_CTX *md_ctx     = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey         = NULL;
    BIO *keybio            = NULL;
    int rc;

    if ( jwt != NULL )
    {
        /* Read the RSA key in from a PEM encoded blob of memory */
        keybio = BIO_new_mem_buf(jwt->key, (int) jwt->keylen);
        if (!keybio)
        {
            return EINVAL;
        }

        pkey = PEM_read_bio_PUBKEY(keybio, NULL, NULL, NULL);
        if (!pkey)
        {
            BIO_free(keybio);
            return EINVAL;
        }

        if ( EVP_PKEY_id( pkey ) != EVP_PKEY_RSA )
        {
            printf("invalid key type\n");
            return EINVAL;
        }

        md_ctx = EVP_MD_CTX_create();
        if ( md_ctx != NULL )
        {
            rc = EVP_DigestVerifyInit( md_ctx,
                                       &pkey_ctx,
                                       jwt->sha,
                                       NULL,
                                       pkey);
            if ( rc == 1 )
            {
                rc = EVP_PKEY_CTX_set_rsa_padding( pkey_ctx, jwt->padding );
                if ( rc > 0 )
                {
                    rc = EVP_DigestVerifyUpdate( md_ctx,
                                                 jwt->pToken,
                                                 jwt->signedlen);
                    if ( rc == 1 )
                    {
                        rc = EVP_DigestVerifyFinal( md_ctx,
                                                    jwt->sig,
                                                    jwt->siglen );
                        if ( rc == 1 )
                        {
                            result = EOK;
                        }
                    }
                }
            }
        }

        BIO_free(keybio);
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(md_ctx);
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
    alg and type attributes.

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

    if ( jwt != NULL )
    {
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
                }
                else
                {
                    /* no 'typ' attribute found */
                    result = ENOTSUP;
                }

                /* free the JSON object */
                JSON_Free( pHeader );
            }
            else
            {
                /* cannot parse JSON header */
                result = ENOTSUP;
            }
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

            JSON_Free( jwt->pPayload );
            jwt->pPayload = NULL;

            result = EOK;
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
            result = ( jwt->claims.iss != NULL ) ? EOK : ENOMEM;
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
            result = ( jwt->claims.sub != NULL ) ? EOK : ENOMEM;
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
            result = ( jwt->claims.jti != NULL ) ? EOK : ENOMEM;
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
                    break;
            }
        }
        else
        {
            /* no 'aud' values found */
            result = ENOENT;
        }

        result = EOK;
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
                result = add_aud_claim( &jwt->claims,
                                        pVar->var.val.str,
                                        1 );
            }
            else
            {
                /* memory allocation failure */
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
                                result = add_aud_claim( &jwt->claims,
                                                        pVar->var.val.str,
                                                        n );
                            }
                        }
                    }
                }
            }
            else
            {
                result = ENOMEM;
            }
        }
        else
        {
            /* empty array */
            result = ENOENT;
        }

    }

    return result;
}

/*============================================================================*/
/*  add_aud_claim                                                             */
/*!
    Add an aud claim value to the claims set

    The aud_add_claim function adds an aud value to the list of
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
static int add_aud_claim( JWTClaims *claims, char *aud, int max_aud )
{
    int result = EINVAL;
    int n;
    char *p;

    if ( ( claims != NULL ) &&
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
                result = ENOMEM;
            }
        }
        else
        {
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

        if ( jwt->pubkeystore != NULL )
        {
            free( jwt->pubkeystore );
            jwt->pubkeystore = NULL;
        }

        if ( jwt->kid != NULL )
        {
            free( jwt->kid );
            jwt->kid = NULL;
        }

        if ( jwt->pubkey != NULL )
        {
            free( jwt->pubkey );
            jwt->pubkey = NULL;
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

        /* clear the JWT object ready for re-use */
        memset( jwt, 0, sizeof( TJWT ) );

        /* deallocate the JWT object */
        free( jwt );

        result = EOK;
    }

    return result;
}

/*! @}
 * end of tjwt group */
