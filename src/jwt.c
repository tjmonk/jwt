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
static char* base64_decode(char* cipher, char *plain, size_t *len);
static int decode_jwt( JWTObj *jwt );
static int verify_rsa( JWTObj *jwt );
static int load_key( JWTObj *jwt );

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
                /* NUL terminate the current section */
                jwt->sections[section][j++] = 0;
                jwt->sectionlen[section] = j;

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
            jwt->sections[section][j++] = 0;
            jwt->sectionlen[section] = j;
            jwt->len = i;
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
/*  base64_decode                                                             */
/*!
    base64 decode an input buffer

    The base64_decode function does a base64 decoding of the input
    buffer and stores the decoded data in the output buffer.

    @param[in]
        cipher
            pointer to the input buffer to be decoded

    @param[in]
        plain
            pointer to an output buffer to store the decoded output

    @param[in,out]
        len
            pointer to the length of the output buffer

    @retval pointer to the output buffer
    @retval NULL if an error occurred

==============================================================================*/
static char* base64_decode(char* cipher, char *plain, size_t *len)
{
    char counts = 0;
    char buffer[4];
    int i = 0;
    int j = 0;
    char k;
    char *p = NULL;
    char c;

    static const char base46_map[] =
        {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
         'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
         'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
         'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
         '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

    if ( ( cipher != NULL ) &&
         ( plain != NULL ) &&
         ( len > 0 ) )
    {
        p = plain;

        while ( ( ( c = cipher[i++] ) != '\0' ) && ( j < *len ))
        {
            for ( k = 0 ;  ( k < 64 ) && ( c != base46_map[k] ) ; k++);

            buffer[counts++] = k;

            if ( counts == 4 )
            {
                p[j++] = (buffer[0] << 2) + (buffer[1] >> 4);
                if (buffer[2] != 64)
                {
                    p[j++] = (buffer[1] << 4) + (buffer[2] >> 2);
                }

                if (buffer[3] != 64)
                {
                    p[j++] = (buffer[2] << 6) + buffer[3];
                }

                counts = 0;
            }
        }

        if ( j < *len )
        {
            *len = j;
            p[j++] = '\0';    /* string padding character */
        }
        else
        {
            *len = j;
        }
    }

    return p;
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
    @retval EINVAL invalid arguments

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
        len = sizeof jwt->header;
        p = base64_decode( jwt->sections[JWT_HEADER_SECTION],
                           jwt->header,
                           &len );

        if ( p != NULL )
        {
            printf( "header: %s, length: %ld\n", p, len );
            jwt->headerlen = len;
        }
        else
        {
            result = EBADMSG;
        }

        len = sizeof jwt->payload;
        p = base64_decode( jwt->sections[JWT_PAYLOAD_SECTION],
                           jwt->payload,
                           &len );

        if ( p != NULL )
        {
            printf( "payload: %s, length: %ld\n", p, len );
            jwt->payloadlen = len;
        }
        else
        {
            result = EBADMSG;
        }

        len = sizeof jwt->sig;
        p = base64_decode( jwt->sections[JWT_SIGNATURE_SECTION],
                           jwt->sig,
                           &len );
        if ( p != NULL )
        {
            printf("sig: length: %ld\n", len );
            jwt->siglen = len;
        }
        else
        {
            result = EBADMSG;
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

    if ( jwt != NULL )
    {
        printf("headerlen: %ld\n", jwt->headerlen);
        printf("payloadlen: %ld\n", jwt->payloadlen);
        printf("siglen: %ld\n", jwt->siglen);
        printf("len: %ld\n", jwt->len);
        printf("padding: %d\n", jwt->padding);

        printf("creation BIO..\n");
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
                                                 jwt->len);
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

#if 0
static int verify_rsa( JWTObj *jwt )
{
    int result = EINVAL;

    EVP_MD_CTX *md_ctx     = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey         = NULL;
    RSA *rsa               = NULL;
    BIO *keybio            = NULL;

    if ( ( jwt != NULL ) &&
         ( jwt->sha != NULL ) &&
         ( jwt->headerlen > 0 ) &&
         ( jwt->payloadlen > 0 ) &&
         ( jwt->siglen > 0 ) &&
         ( jwt->payloadlen > 0 ) &&
         ( jwt->len > 0 ) )
    {
        /* Read the RSA key in from a PEM encoded blob of memory */
        keybio = BIO_new_mem_buf(jwt->key, (int) jwt->keylen);
        if ( keybio != NULL )
        {
            rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
            BIO_free(keybio);
            if (!rsa) {
                return EINVAL;
            }

            pkey   = EVP_PKEY_new();
            md_ctx = EVP_MD_CTX_create();

            if ( ( md_ctx && pkey
                 ( EVP_PKEY_assign_RSA( pkey, rsa ) == 1 ) &&
                 ( EVP_DigestInit_ex( md_ctx, jwt->sha, NULL ) == 1 ) &&
                 ( EVP_DigestVerifyInit( md_ctx, &pkey_ctx, jwt->sha, NULL, pkey ) == 1 ) &&
                 ( EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, jwt->padding) > 0 ) &&
                 ( EVP_DigestVerifyUpdate(md_ctx, jwt->pToken, jwt->len ) == 1 ) &&
                 ( EVP_DigestVerifyFinal(md_ctx, jwt->sig, jwt->siglen) == 1 ) )
            {
                result = EOK;
            }

            if ( pkey != NULL )
            {
                EVP_PKEY_free(pkey);
            }

            if ( md_ctx != NULL )
            {
                EVP_MD_CTX_free(md_ctx);
            }
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}
#endif

/*! @}
 * end of jwt group */
