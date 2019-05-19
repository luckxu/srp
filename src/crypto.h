#ifndef __SRP_CRYPTO_H__
#define __SRP_CRYPTO_H__
#include "common.h"

typedef enum {
    e_rsa_key_pri = 0, //私钥类型
    e_rsa_key_pub      //公钥类型
} e_rsa_key_type;

int generate_rsa_keypair(rsa_keys_t *keys, int32_t bits);
int generate_aes_keypair(aes_keys_t *keys, int32_t bits, uint8_t *key_str);

RSA *create_rsa_key(char *key, e_rsa_key_type type);
//加密和签名结果长度计算
#define encrypt_length(srclen)                                                                                         \
    (int32_t)((((int32_t)(srclen) + RSA_ENCRYPT_CHUNK_BYTES - 1) / RSA_ENCRYPT_CHUNK_BYTES) *                          \
                  RSA_DECRYPT_CHUNK_BYTES +                                                                            \
              SIGN_CHUNK_BYTES)
#define decrypt_length(srclen)                                                                                         \
    (int32_t)((((int32_t)(srclen)-SIGN_CHUNK_BYTES) / RSA_DECRYPT_CHUNK_BYTES) * RSA_ENCRYPT_CHUNK_BYTES)

int32_t rsa_private_encrypt(RSA *rsa_key, uint8_t *in, int32_t inlen, uint8_t *out, int32_t outlen);
int32_t rsa_public_decrypt(RSA *rsa_pub, uint8_t *in, int32_t inlen, uint8_t *out, int32_t outlen);
int32_t rsa_private_decrypt(RSA *rsa_key, uint8_t *in, int32_t inlen, uint8_t *out, int32_t outlen);
int32_t rsa_public_encrypt(RSA *rsa_pub, uint8_t *in, int32_t inlen, uint8_t *out, int32_t outlen);
uint32_t aes_encrypt(const AES_KEY *key, uint8_t *in, int32_t inlen, uint8_t *out, int32_t outlen);
uint32_t aes_decrypt(const AES_KEY *key, uint8_t *in, int32_t inlen, uint8_t *out, int32_t outlen);

#define signature_length(srclen) (encrypt_length(srclen) + SIGN_CHUNK_BYTES)
int32_t encrypt_and_signature(RSA *enc_pub, RSA *sign_key, uint8_t *in, int32_t inlen, uint8_t *out, int32_t outlen);
int32_t decrypt_and_verification(RSA *rsa_pub, RSA *dec_key, uint8_t *in, int32_t inlen, uint8_t *out, int32_t outlen);
#endif