#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "crypto.h"
#include "common.h"

/**
 * @brief RSA算法私钥加密，加密后数据会比原数据长，调用者需保证out空间足够
 *
 * @param in 输入数据
 * @param inlen 输入数据字节长度
 * @param out 加密后数据
 * @return int32_t 加密数据长度, -1表示加密错误
 */
int32_t rsa_private_encrypt(RSA *rsa_key, uint8_t *in, int32_t inlen, uint8_t *out, int32_t outlen) {
    int32_t rsalen, flen, retlen;
    int32_t inpos, outpos;
    assert(in && out && inlen > 0 && outlen > 0);
    if (encrypt_length(inlen) > outlen)
        return -1;
    rsalen = RSA_size(rsa_key);
    flen = rsalen - 12;
    inpos = outpos = 0;
    while (inpos < inlen) {
        if (inlen - inpos < flen)
            flen = inlen - inpos;
        if ((retlen = RSA_private_encrypt(flen, in + inpos, out + outpos, rsa_key, RSA_PKCS1_PADDING)) < 0) {
            ERR_print_errors_fp(stdout);
            outpos = 0;
            break;
        }
        inpos += flen;
        outpos += retlen;
    }
    return outpos;
}

/**
 * @brief RSA算法私钥解密，解密后数据长度比原数据短
 *
 * @param in 公钥加密数据
 * @param inlen 加密数据长度
 * @param out 解密数据
 * @return int32_t 解密数据长度, -1表示解密错误
 */
int32_t rsa_private_decrypt(RSA *rsa_key, uint8_t *in, int32_t inlen, uint8_t *out, int32_t outlen) {
    int32_t rsalen, flen, retlen;
    int32_t inpos, outpos;
    assert(in && out && inlen > 0 && outlen > 0);
    if (decrypt_length(inlen) > outlen)
        return -1;
    rsalen = RSA_size(rsa_key);
    flen = rsalen;
    inpos = outpos = 0;
    while (inpos < inlen) {
        if (inlen - inpos < rsalen)
            flen = inlen - inpos;
        if ((retlen = RSA_private_decrypt(flen, in + inpos, out + outpos, rsa_key, RSA_PKCS1_PADDING)) < 0) {
            ERR_print_errors_fp(stdout);
            outpos = 0;
            break;
        }
        inpos += flen;
        outpos += retlen;
    }
    return outpos;
}

/**
 * @brief RSA算法公钥加密，加密后数据会比原数据长，调用者需保证out空间足够
 *
 * @param in 输入数据
 * @param inlen 输入数据字节长度
 * @param out 加密后数据
 * @return int32_t 加密数据长度, -1表示加密错误
 */
int32_t rsa_public_encrypt(RSA *rsa_pub, uint8_t *in, int32_t inlen, uint8_t *out, int32_t outlen) {
    int32_t rsalen, flen, retlen;
    int32_t inpos, outpos;
    assert(in && out && inlen > 0 && outlen > 0);
    if (encrypt_length(inlen) > outlen)
        return -1;

    rsalen = RSA_size(rsa_pub);
    flen = rsalen - 12;
    inpos = outpos = 0;
    while (inpos < inlen) {
        if (inlen - inpos < flen)
            flen = inlen - inpos;
        if ((retlen = RSA_public_encrypt(flen, in + inpos, out + outpos, rsa_pub, RSA_PKCS1_PADDING)) < 0) {
            ERR_print_errors_fp(stdout);
            outpos = 0;
            break;
        }
        inpos += flen;
        outpos += retlen;
    }
    return outpos;
}

/**
 * @brief RSA算法公钥解密，解密后数据长度比原数据短
 *
 * @param in 公钥加密数据
 * @param inlen 加密数据长度
 * @param out 解密数据
 * @return int32_t 解密数据长度, -1表示解密错误
 */
int32_t rsa_public_decrypt(RSA *rsa_pub, uint8_t *in, int32_t inlen, uint8_t *out, int32_t outlen) {
    int32_t rsalen, flen, retlen;
    int32_t inpos, outpos;

    assert(in && out && inlen > 0 && outlen > 0);
    if (decrypt_length(inlen) > outlen)
        return -1;
    rsalen = RSA_size(rsa_pub);
    flen = rsalen;
    inpos = outpos = 0;
    while (inpos < inlen) {
        if (inlen - inpos < rsalen)
            flen = inlen - inpos;
        if ((retlen = RSA_public_decrypt(flen, in + inpos, out + outpos, rsa_pub, RSA_PKCS1_PADDING)) < 0) {
            ERR_print_errors_fp(stdout);
            outpos = 0;
            break;
        }
        inpos += flen;
        outpos += retlen;
    }
    return outpos;
}

/**
 * @brief 从内存区读取公钥和私钥
 *
 * @param key 公钥或私钥字符串
 * @param begin_str 头部字串
 * @param end_str 尾部字串
 * @param type 密钥类型，TYPE_KEY为私钥, TYPE_PUB为公钥
 * @return RSA* RSA句柄
 */
RSA *create_rsa_key(char *keystr, e_rsa_key_type type) {
    BIO *bio = NULL;
    RSA *rsa = NULL;

    //从内存中读取RSA公钥
    if ((bio = BIO_new_mem_buf(keystr, -1)) == NULL) {
        log_err("BIO_new_mem_buf failed");
        ERR_print_errors_fp(stdout);
        return NULL;
    }
    //从bio结构中得到rsa结构
    if (type == e_rsa_key_pri)
        rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    else
        rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if (!rsa) {
        ERR_load_crypto_strings();
        ERR_print_errors_fp(stdout);
    }
    return rsa;
}

int generate_rsa_keypair(rsa_keys_t *keys, int32_t bits) {
    struct timeval tv;
    int32_t pub_len;
    keys->pri_rsa = RSA_new();
    BIGNUM *e = BN_new();
    gettimeofday(&tv, NULL);
    srand(tv.tv_usec);
    BN_set_word(e, (unsigned long)rand() | 1);

    // 生成密钥对
    RSA_generate_key_ex(keys->pri_rsa, 2048, e, NULL);

    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSA_PUBKEY(pub, keys->pri_rsa);

    // 获取长度
    pub_len = BIO_pending(pub);

    // 密钥对读取到字符串
    keys->pub_str = (uint8_t *)malloc(pub_len + 1);

    BIO_read(pub, keys->pub_str, pub_len);

    keys->pub_str[pub_len] = '\0';

    keys->pub_rsa = create_rsa_key((char *)keys->pub_str, e_rsa_key_pub);
    return 0;
}

int generate_aes_keypair(aes_keys_t *keys, int32_t bits, uint8_t *key_str) {
    int fd;
    if (!key_str) {
        fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) {
            log_err("open urandom device failed");
            return -1;
        }
        read(fd, keys->key, AES_KEY_BYTES);
        close(fd);
    } else
        memcpy(keys->key, key_str, AES_KEY_BYTES);
    AES_set_decrypt_key(keys->key, AES_KEY_BITS, &keys->dec_aes);
    AES_set_encrypt_key(keys->key, AES_KEY_BITS, &keys->enc_aes);
    return 0;
}
/**
 * @brief 公钥加密和私钥签名处理程序
 * 调用程序应该检测out和返回值是否相同，不同表示内部重新分配了空间，**注意内存释放问题**
 *
 * @param in 待加密原始数据
 * @param inlen 原始数据长度
 * @param out 加密结果输出，如果为NULL则由函数自己分配空间
 * @param outlen out空间长度，当长度不够时内部分配空间
 * @return int32_t 加密结果长度，-1表示错误
 */
int32_t encrypt_and_signature(RSA *enc_pub, RSA *sign_key, uint8_t *in, int32_t inlen, uint8_t *out, int32_t outlen) {
    int32_t retlen;
    uint8_t hash[SHA256_DIGEST_LENGTH];
    uint32_t real = signature_length(inlen);
    assert(enc_pub && sign_key && in && out && inlen > 0 && outlen > 0 && real <= outlen);

    do {
        //公钥加密原始数据
        if ((retlen = rsa_public_encrypt(enc_pub, in, inlen, out + SIGN_CHUNK_BYTES, outlen - SIGN_CHUNK_BYTES)) <= 0) {
            log_warn("rsa_public_encrypt failed");
            break;
        }
        //生成原始数据的指纹
        SHA256(in, inlen, hash);

        //使用私钥对原始数据的sha256指纹签名并放置在数据之前
        if ((retlen = rsa_private_encrypt(sign_key, hash, SHA256_DIGEST_LENGTH, out, SIGN_CHUNK_BYTES)) <= 0) {
            log_warn("rsa_private_encrypt failed");
            break;
        }
        return real;
    } while (0);
    return -1;
}

/**
 * @brief 公钥验签和私钥解密处理程序
 * 调用程序应该检测out和返回值是否相同，不同表示内部重新分配了空间，**注意内存释放问题**
 *
 * @param in 待加密原始数据
 * @param inlen 原始数据长度
 * @param out 加密结果输出，如果为NULL则由函数自己分配空间
 * @param outlen out空间长度，当长度不够时内部分配空间
 * @return int32_t 解密数据长度，-1表示错误
 */
int32_t decrypt_and_verification(RSA *rsa_pub, RSA *dec_key, uint8_t *in, int32_t inlen, uint8_t *out, int32_t outlen) {
    int32_t retlen;
    uint8_t hash1[SIGN_CHUNK_BYTES], hash2[SHA256_DIGEST_LENGTH];
    uint32_t real;
    assert(rsa_pub && dec_key && in && out && inlen > 0 && outlen > 0);

    real = decrypt_length(inlen - SIGN_CHUNK_BYTES);
    assert(real <= outlen);

    do {
        //私钥解密
        if ((retlen = rsa_private_decrypt(dec_key, in + SIGN_CHUNK_BYTES, inlen - SIGN_CHUNK_BYTES, out, outlen)) <=
            0) {
            log_warn("rsa_private_encrypt failed");
            break;
        }
        //计算解密结果的sha256指纹
        SHA256(out, retlen, hash1);
        //公钥解密签名部分
        if (rsa_public_decrypt(rsa_pub, in, SIGN_CHUNK_BYTES, hash2, SIGN_CHUNK_BYTES) != SHA256_DIGEST_LENGTH) {
            log_warn("rsa_public_decrypt failed");
            break;
        }
        //比对生成的签名是否同解密出的签名一致
        if (!memcmp(hash1, hash2, SHA256_DIGEST_LENGTH))
            return real;
    } while (0);
    return -1;
}

/**
 * @brief aes解密函数，输入必须AES_BLOCK_SIZE字节对接
 *
 * @param key 密钥句柄
 * @param in 原始加密数据
 * @param inlen 原始加密数据长度
 * @param out 解密结果内存指针
 * @param outlen 解密结果内存长度
 * @return int32_t 解密数据长度，0表示错误
 */
uint32_t aes_decrypt(const AES_KEY *key, uint8_t *in, int32_t inlen, uint8_t *out, int32_t outlen) {
    uint32_t i;
    assert(in && out);
    if ((inlen & (AES_BLOCK_SIZE - 1)) || outlen < inlen)
        return 0;
    for (i = 0; i < inlen; i += AES_BLOCK_SIZE) {
        AES_decrypt(in + i, out + i, key);
    }
    return i;
}

/**
 * @brief aes加密函数，如果输入不是AES_BLOCK_SIZE字节对接，则尾部添零对齐
 *
 * @param in 原始数据
 * @param len 原始数据长度
 * @param out 加密结果
 * @param key 密钥句柄
 * @return int32_t 加密结果长度，0表示加密失败
 */
uint32_t aes_encrypt(const AES_KEY *key, uint8_t *in, int32_t inlen, uint8_t *out, int32_t outlen) {
    uint8_t buf[AES_BLOCK_SIZE];
    int32_t i, real;
    assert(out && in && inlen > 0 && outlen > 0);
    real = ((inlen + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    if (outlen < real)
        return 0;
    for (i = 0; i < inlen; i += AES_BLOCK_SIZE) {
        if (inlen - i < AES_BLOCK_SIZE) {
            memcpy(buf, in + i, inlen - i);
            memset(buf + inlen - i, 0, AES_BLOCK_SIZE + i - inlen);
            AES_encrypt(buf, out + i, key);
        } else
            AES_encrypt(in + i, out + i, key);
    }
    return i;
}
