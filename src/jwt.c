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
 * @defgroup jwt JSON Web Token
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
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

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
    char sections[JWT_MAX_NUM_SECTIONS][JWT_MAX_SECTION_LEN];

    /*! stores the length of each encoded JWT section */
    size_t sectionlen[JWT_MAX_NUM_SECTIONS];

    /*! base64 decoded header */
    char header[JWT_MAX_HEADER_LEN];

    /*! decoded header length */
    size_t headerlen;

    /*! base64 decoded payload */
    char payload[JWT_MAX_PAYLOAD_LEN];

    /*! length of the decoded payload */
    size_t payloadlen;

    /*! base64 decoded signature */
    char sig[JWT_MAX_SIG_LEN];

    /*! length of the decoded signature */
    size_t siglen;

    /*! pointer to the validating key */
    char key[JWT_MAX_KEY_LEN];

    /*! length of the validation key */
    size_t keylen;

} JWTObj;

/*==============================================================================
        Private function declarations
==============================================================================*/

static int split( const char *in, JWTObj *jwt );
static int PrintSections( JWTObj *jwt );
static int decode_jwt( JWTObj *jwt );
static int verify_rsa( JWTObj *jwt );
static int load_key( JWTObj *jwt );

static size_t b64url_decode( const uint8_t *in,
                             size_t len,
                             uint8_t *out,
                             const size_t outlen );

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
    int result = EINVAL;
    JWTObj jwt;

    if ( argc != 2 )
    {
        printf( "usage: jwt <encoded jwt>\n");
        exit(1);
    }

    memset( &jwt, 0, sizeof jwt );

    jwt.keyfile = "public.key";
    jwt.padding = RSA_PKCS1_PADDING;
    jwt.sha = EVP_sha256();

    printf("loading key...\n");
    result = load_key( &jwt );
    if ( result == EOK )
    {
        printf("splitting token...\n");
        result = split( argv[1], &jwt );
        if ( result == EOK )
        {
            printf("unencoded header length: %ld\n",
                    jwt.sectionlen[JWT_HEADER_SECTION]);

            printf("unencoded payload length: %ld\n",
                    jwt.sectionlen[JWT_PAYLOAD_SECTION]);

            printf("unencoded signature length: %ld\n",
                    jwt.sectionlen[JWT_SIGNATURE_SECTION]);

            printf("printing sections..\n");
            result = PrintSections( &jwt );
            if ( result == EOK )
            {
                printf("base64 decoding...\n");
                result = decode_jwt( &jwt );
                if ( result == EOK )
                {
                    printf("verify rsa...\n");
                    result = verify_rsa( &jwt );
                }
            }
        }
    }

    if( result != EOK )
    {
        printf("result: %s\n", strerror(result));
    }

    return result == EOK ? 0 : 1;
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
static int split( const char *in, JWTObj *jwt )
{
    int i = 0;
    int j = 0;
    int section = 0;
    size_t len;
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
                jwt->sections[section][j++] = c;
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
static int PrintSections( JWTObj *jwt )
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
static int decode_jwt( JWTObj *jwt )
{
    int result = EINVAL;
    char *p;
    size_t len;

    if ( jwt != NULL )
    {
        /* assume everything is ok until it is not */
        result = EOK;

        /* decode the header */
        len = b64url_decode( jwt->sections[JWT_HEADER_SECTION],
                             jwt->sectionlen[JWT_HEADER_SECTION],
                             jwt->header,
                             sizeof jwt->header );
        printf( "header: %s, length: %ld\n", jwt->header, len );
        jwt->headerlen = len;
        if ( len == 0 )
        {
            result = EINVAL;
        }

        /* decode the payload */
        len = b64url_decode( jwt->sections[JWT_PAYLOAD_SECTION],
                             jwt->sectionlen[JWT_PAYLOAD_SECTION],
                             jwt->payload,
                             sizeof jwt->payload );
        printf( "payload: %s, length: %ld\n", jwt->payload, len );
        jwt->payloadlen = len;
        if ( len == 0 )
        {
            result = EINVAL;
        }

        len = b64url_decode( jwt->sections[JWT_SIGNATURE_SECTION],
                             jwt->sectionlen[JWT_SIGNATURE_SECTION],
                             jwt->sig,
                             sizeof jwt->sig );
        printf("sig: length: %ld\n", len );
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
static int load_key( JWTObj *jwt )
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
static int verify_rsa( JWTObj *jwt )
{
    int result = EINVAL;

    EVP_MD_CTX *md_ctx     = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey         = NULL;
    BIO *keybio            = NULL;
    int rc;
    size_t len;

    if ( jwt != NULL )
    {
        printf("headerlen: %ld\n", jwt->headerlen);
        printf("payloadlen: %ld\n", jwt->payloadlen);
        printf("siglen: %ld\n", jwt->siglen);
        printf("len: %ld\n", jwt->len);
        printf("signedlen = %ld\n", jwt->signedlen);
        printf("padding: %d\n", jwt->padding);
        printf("keylen=%ld\n", jwt->keylen);
        printf("pToken : %s\n", jwt->pToken);
        printf("creation BIO..\n");

        printf("validating payload: %.*s\n", (int)jwt->signedlen, jwt->pToken );

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
            printf("EVP_DigestVerifyInit...\n");
            rc = EVP_DigestVerifyInit( md_ctx,
                                       &pkey_ctx,
                                       jwt->sha,
                                       NULL,
                                       pkey);
            if ( rc == 1 )
            {
                printf("EVP_PKEY_CTX_set_rsa_padding..\n");

                rc = EVP_PKEY_CTX_set_rsa_padding( pkey_ctx, jwt->padding );
                if ( rc > 0 )
                {
                    printf("EVP_DigestVerifyUpdate...\n");
                    rc = EVP_DigestVerifyUpdate( md_ctx,
                                                 jwt->pToken,
                                                 jwt->signedlen);
                    if ( rc == 1 )
                    {
                        printf("EVP_DigestVerifyFinal...\n");
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
    int bit_count  = 0;
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
                bit_count += 6;

                /* check if we have collected enough to emit an 8-bit value */
                if ( bit_count >= 8 )
                {
                    /* emit an 8 bit value */
                    out[n++] = (uint8_t) (0xff & (bits >> (bit_count - 8)));

                    /* reduce the bit count by the number of bits emitted */
                    bit_count -= 8;
                }
            }
        }
    }

    return ( i < len ) ? 0 : n;
}

/*! @}
 * end of jwt group */
