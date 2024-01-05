/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c

Written By: 
     1- Zoe Zinn
Submitted on: 9/18/23
----------------------------------------------------------------------------*/

#include "myCrypto.h"

void handleErrors( char *msg)
{
    fprintf( stderr , "%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    abort();
}

//----------------------------------------------------------------------------
// Encrypt the plain text stored at 'pPlainText' into the
// caller-allocated memory at 'pCipherText'
// Caller must allocate sufficient memory for the cipher text
// Returns size of the cipher text in bytes

unsigned encrypt( uint8_t *pPlainText, unsigned plainText_len,
                const uint8_t *key, const uint8_t *iv, uint8_t *pCipherText )
{
    int      status ;
    unsigned len = 0, encryptedLen = 0 ;

    /* Create and initialize the context*/
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new() ;
    if( ! ctx )
    {
        handleErrors("encrypt: failed to create CTX") ;
    } 

    // Initialize the encryption operation.
    status = EVP_EncryptInit_ex( ctx, ALGORITHM(), NULL, key, iv ) ;
    if (status != 1)
    {
        handleErrors("encrypt: failed to EncryptInit_ex");
    }

    // Call EncryptUpdate as many times as needed (e.g. inside a loop)
    // to perform regular encryption
    status = EVP_EncryptUpdate( ctx, pCipherText, &len, pPlainText, plainText_len) ;
    if (status != 1)
    {
        handleErrors("encrypt: failed to  EncryptUpdate") ;
    }
    encryptedLen += len ;

    // If additional ciphertext may still be generated,
    // the pCipherText pointer must be first advanced forward
    pCipherText += len ;

    // Finalize the Encryption.
    status = EVP_EncryptFinal_ex( ctx, pCipherText , &len) ;
    if (status != 1)
    {
        handleErrors("encrypt: failed to EncryptFinal_ex") ;
    }

    encryptedLen += len; // len could be 0 if no additional ciphertext was generated

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return encryptedLen ;
}

//----------------------------------------------------------------------------
// Decrypt the cipher text stored at 'pCipherText' into the
// caller-allocated memory at 'pDecryptedText'
// Caller must allocate sufficient memory for the decrypted text
// Returns size of the decrypted text in bytes

unsigned decrypt( uint8_t *pCipherText, unsigned cipherText_len,
                const uint8_t *key, const uint8_t *iv, uint8_t *pDecryptedText)
{
    int      status ;
    unsigned len = 0, decryptedLen = 0 ;

    /* Create and initialize the context*/
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new() ;
    if( ! ctx )
    {
        handleErrors("decrypt: failed to create CTX") ;
    } 

    // Initialize the decryption operation.
    status = EVP_DecryptInit_ex( ctx, ALGORITHM(), NULL, key, iv ) ;
    if (status != 1)
    {
        handleErrors("decrypt: failed to DecryptInit_ex");
    }

    // Call DecryptUpdate as many times as needed (e.g. inside a loop)
    // to perform regular decryption
    status = EVP_DecryptUpdate( ctx, pDecryptedText, &len, pCipherText, cipherText_len) ;
    if (status != 1)
    {
        handleErrors("decrypt: failed to  DecryptUpdate") ;
    }
    decryptedLen += len ;

    // If additional decrypted text may still be generated,
    // the pDecryptedText pointer must be first advanced forward
    pDecryptedText += len ;

    // Finalize the Decryption.
    status = EVP_DecryptFinal_ex( ctx, pDecryptedText , &len) ;
    if (status != 1)
    {
        handleErrors("decrypt: failed to DecryptFinal_ex") ;
    }
    decryptedLen += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return decryptedLen ;
}

//-----------------------------------------------------------------------------

static unsigned char   plaintext [ PLAINTEXT_LEN_MAX ] , 
                       ciphertext[ CIPHER_LEN_MAX    ] ,
                       decryptext[ DECRYPTED_LEN_MAX ] ;

// above arrays being static to resolve runtime stack size issue. 
// However, that makes the code non-reentrant for multithreaded application
//-----------------------------------------------------------------------------


int encryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{

    uint8_t plainBlock[PLAINTEXT_LEN_MAX];
    uint8_t cipherBlock[CIPHER_LEN_MAX];
    int bytesRead, bytesWritten;

    memset(plainBlock, 0, PLAINTEXT_LEN_MAX);
    memset(cipherBlock, 0, CIPHER_LEN_MAX);


    // Set up the encryption
    int      status;
    unsigned len = 0, encryptedLen = 0;
    

    // Create and initialize the context 
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
    {
        handleErrors("encryptFile: failed to create CTX");
    } 


    // Initialize the encryption operation.
    status = EVP_EncryptInit_ex( ctx, ALGORITHM(), NULL, key, iv ) ;
    if (status != 1)
    {
        handleErrors("encryptFile: failed to EncryptInit_ex");
    }


    // Do the encryption
    bytesRead = read(fd_in, plainBlock, PLAINTEXT_LEN_MAX);
    while (bytesRead > 0)
        {
            status = EVP_EncryptUpdate(ctx, cipherBlock, &len, plainBlock, bytesRead);
            if (status != 1)
            {
                handleErrors("encryptFile: failed to  EncryptUpdate");
            }
            encryptedLen += len;

            bytesWritten = write(fd_out, cipherBlock, len);
            if (bytesWritten == -1)
            {
                handleErrors("encryptFile: failed to write to data channel");
            }

            memset(plainBlock, 0, PLAINTEXT_LEN_MAX);
            memset(cipherBlock, 0, CIPHER_LEN_MAX);

            bytesRead = read(fd_in, plainBlock, PLAINTEXT_LEN_MAX);
        }
    if (bytesRead == -1)
    {
        handleErrors("encryptFile: could not read plaintext");
    }


    // Finalize the encryption
    status = EVP_EncryptFinal_ex(ctx, cipherBlock, &len);
    if (status != 1)
    {
        handleErrors("encryptFile: failed to EncryptFinal_ex") ;
    }

    bytesWritten = write(fd_out, cipherBlock, len);
    if (bytesWritten == -1)
    {
        handleErrors("encryptFile: failed to write to data channel");
    }
    encryptedLen += len; // len could be 0 if no additional ciphertext was generated


    // Clean up
    EVP_CIPHER_CTX_free(ctx);


    return encryptedLen ;
}

//-----------------------------------------------------------------------------


int decryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{
    uint8_t cipherBlock[CIPHER_LEN_MAX];
    uint8_t decryptBlock[PLAINTEXT_LEN_MAX];
    int      status;
    unsigned len = 0, decryptedLen = 0;
    int bytesRead, bytesWritten;

    memset(cipherBlock, 0, CIPHER_LEN_MAX);
    memset(decryptBlock, 0, PLAINTEXT_LEN_MAX);


    // Create and initialize the context 
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if( ! ctx )
    {
        handleErrors("decryptFile: failed to create CTX");
    } 


    // Initialize the decryption operation.
    status = EVP_DecryptInit_ex( ctx, ALGORITHM(), NULL, key, iv );
    if (status != 1)
    {
        handleErrors("decryptFile: failed to DecryptInit_ex");
    }


    // Do the decryption
    bytesRead = read(fd_in, cipherBlock, CIPHER_LEN_MAX);
    while (bytesRead > 0)
        {
            status = EVP_DecryptUpdate(ctx, decryptBlock, &len, cipherBlock, bytesRead);
            if (status != 1)
            {
                handleErrors("decryptFile: failed to  DecryptUpdate");
            }
            decryptedLen += len;

            bytesWritten = write(fd_out, decryptBlock, len);
            if (bytesWritten == -1)
            {
                handleErrors("decryptFile: failed to write to data channel");
            }

            memset(cipherBlock, 0, CIPHER_LEN_MAX);
            memset(decryptBlock, 0, PLAINTEXT_LEN_MAX);

            bytesRead = read(fd_in, cipherBlock, CIPHER_LEN_MAX);
        }
    if (bytesRead == -1)
    {
        handleErrors("decryptFile: could not read ciphertext");
    }


    // Finalize the Decryption
    status = EVP_DecryptFinal_ex(ctx, decryptBlock , &len) ;
    if (status != 1)
    {
        handleErrors("decryptFile: failed to DecryptFinal_ex");
    }
    decryptedLen += len;

    bytesWritten = write(fd_out, decryptBlock, len);
    if (bytesWritten == -1)
    {
        handleErrors("decryptFile: failed to write to data channel");
    }
    decryptedLen += len;


    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);


    return decryptedLen ;
}
