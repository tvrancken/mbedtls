/**
 * \file quantum_relief.h
 *
 * \brief Quantum Hardening TLS
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef MBEDTLS_QUANTUM_RELIEF_H
#define MBEDTLS_QUANTUM_RELIEF_H
//include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

/*** Module-specific error codes ***/
/* Detected an extension that is incompatible with ours */
#define MBEDTLS_ERR_QR_INCOMPATIBLE_EXTENSION        -10
/* Got an illegal configuration setting */
//define MBEDTLS_ERR_QR_ILLEGAL_CONFIGURATION         -11
/* Received a request for an unknown QR method */
#define MBEDTLS_ERR_QR_UNKOWN_METHOD_REQUESTED       -12
/* Received a request for an illegal QR method (e.g., not proposed) */
#define MBEDTLS_ERR_QR_ILLEGAL_METHOD_REQUESTED      -13


#ifdef __cplusplus
extern "C" {
#endif

/*** Public data types ***/

/**
 * \brief          Quantum Relief methods
 */
typedef enum {
    MBEDTLS_QR_METHOD_NONE = 0,
    MBEDTLS_QR_METHOD_KDH
} mbedtls_qr_method_t;

/*** Public functions and APIs ***/
/* Setters for configuration values are declared in ssl.h */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_QUANTUM_RELIEF_H */
