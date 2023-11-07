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
#ifndef TJWT_OBJ_H
#define TJWT_OBJ_H

/*==============================================================================
        Includes
==============================================================================*/

#include <tjson/json.h>
#include <tjwt/tjwt.h>

/*==============================================================================
        Definitions
==============================================================================*/

#ifndef JWT_MAX_SECTION_LEN
/*! maximum length of each section of a JWT */
#define JWT_MAX_SECTION_LEN ( 1024 )
#endif

#ifndef JWT_MAX_NUM_SECTIONS
/*! maximum supported sections in a JWT */
#define JWT_MAX_NUM_SECTIONS ( 3 )
#endif

/*! max JWT header length */
#ifndef JWT_MAX_HEADER_LEN
#define JWT_MAX_HEADER_LEN ( 128 )
#endif

/*! max JWT payload length */
#ifndef JWT_MAX_PAYLOAD_LEN
#define JWT_MAX_PAYLOAD_LEN ( 256 )
#endif

/*! max JWT signature length */
#ifndef JWT_MAX_SIG_LEN
#define JWT_MAX_SIG_LEN ( 1024 )
#endif

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
    char *key;

    /*! length of the validation key */
    size_t keylen;

    /*! verification function */
    int (*verify)( struct _jwt_obj * );

    /*! verification algorithm name */
    char *alg;

    /*! pointer to the JSON payload */
    JNode *pPayload;

    /* pointer to the name of the key store */
    char *keystore;

    /*! pointer to the key ID string */
    char *kid;

    /*! pointer to the expected audience string */
    char *aud;

    /*! pointer to the expected issuer string */
    char *iss;

    /*! pointer to the expected subject string */
    char *sub;

    /*! JWT claims */
    JWTClaims claims;

    /*! clock skew */
    int clockskew;

    /*! time */
    int64_t timestamp;

    /*! error code */
    uint32_t error;

} TJWT;

#endif
