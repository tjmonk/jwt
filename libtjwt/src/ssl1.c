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
 * @defgroup ssl SSL functions for JWT verification
 * @brief SSL functions for JWT signature verification
 * @{
 */

/*============================================================================*/
/*!
@file ssl3.c

    SSL3 JWT Verification

    The SSL3 JWT Verification component peforms JWT signature verification
    using the OpenSSL 3.x library

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
#include <tjson/json.h>
#include <errno.h>
#include <tjwt/tjwt.h>
#include "tjwt_obj.h"

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
int verify_rsa( TJWT *jwt )
{
    int result = EINVAL;

    EVP_MD_CTX *md_ctx     = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey         = NULL;
    BIO *keybio            = NULL;
    RSA *rsa               = NULL;
    int rc;

    if ( jwt != NULL )
    {
        /* Read the RSA key in from a PEM encoded blob of memory */
        keybio = BIO_new_mem_buf(jwt->key, (int) jwt->keylen);
        if (keybio)
        {
            /* get rsa public key */
            rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
            if (rsa != NULL )
            {
                /* create a new private key object */
                pkey = EVP_PKEY_new();

                /* create a new digest context */
                md_ctx = EVP_MD_CTX_create();
                if ( ( md_ctx != NULL ) &&
                    ( pkey != NULL ) )
                {
                    rc = EVP_PKEY_assign_RSA(pkey, rsa);
                    if ( rc == 1 )
                    {
                        /* set up digest context to use digest type
                           specified by jwt->sha */
                        rc = EVP_DigestInit_ex( md_ctx, jwt->sha, NULL );
                        if ( rc == 1 )
                        {
                            /* set up verification context */
                            rc = EVP_DigestVerifyInit( md_ctx,
                                                    &pkey_ctx,
                                                    jwt->sha,
                                                    NULL,
                                                    pkey );
                            if ( rc == 1 )
                            {
                                /* apply RSA padding as appropriate */
                                rc = EVP_PKEY_CTX_set_rsa_padding( pkey_ctx,
                                                                jwt->padding );
                                if ( rc > 0 )
                                {
                                    /* hash the input token
                                        (header + . + payload ) */
                                    rc = EVP_DigestVerifyUpdate(md_ctx,
                                                                jwt->pToken,
                                                                jwt->signedlen);
                                    if ( rc == 1 )
                                    {
                                        /* verify the data against the
                                           signature */
                                        rc = EVP_DigestVerifyFinal(md_ctx,
                                                                   jwt->sig,
                                                                   jwt->siglen);
                                        if ( rc == 1 )
                                        {
                                            result = EOK;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }


        if ( keybio != NULL )
        {
            BIO_free(keybio);
        }

        if ( pkey != NULL )
        {
            EVP_PKEY_free(pkey);
        }

        if ( md_ctx != NULL )
        {
            EVP_MD_CTX_free(md_ctx);
        }

        if ( result != EOK )
        {
            jwt->error |= ( 1L << TJWT_ERR_SIGNATURE_VERIFY );
        }
    }

    return result;

}

/*! @}
 * end of ssl group */
