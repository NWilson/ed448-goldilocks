/**
 * @file config.h
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Goldilocks top-level configuration flags.
 */

#ifndef __GOLDILOCKS_CONFIG_H__
#define __GOLDILOCKS_CONFIG_H__ 1

/**
 * @brief Goldilocks uses libpthread mutexes to provide
 * thread-safety.  If you disable this flag, it won't link
 * libpthread, but it won't be thread-safe either.
 */
#define GOLDILOCKS_USE_PTHREAD          0

/**
 * @brief Experiment to change the hash inputs for ECDH,
 * in a way that obliterates the result -- overwriting it with
 * a safe pseudorandom value -- if the public key is invalid.
 * That way users who ignore the status result won't be
 * exposed to invalid key attacks. 
 */
#define EXPERIMENT_ECDH_OBLITERATE_CT   1

/**
 * @brief Whether or not define the signing functions, which
 * currently require SHA-512.
 */
#define GOLDI_IMPLEMENT_SIGNATURES      1

/**
 * @brief Whether or not to define and implement functions
 * working with pre-computed keys.
 */
#define GOLDI_IMPLEMENT_PRECOMPUTED_KEYS 0

/**
 * @brief ECDH adds public keys into the hash, to prevent
 * esoteric attacks.
 */
#define EXPERIMENT_ECDH_STIR_IN_PUBKEYS 1

#endif /* __GOLDILOCKS_CONFIG_H__ */
