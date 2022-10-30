/**
 * \file quantum_relief_kdh.h
 *
 * \brief Quantum Relief module: Kerberized Diffie-Hellman (KDH) QR method
 *
 * This file is part of the Quantum Relief extension as
 * defined in TODO: spec (TODO: url).
 *
 * The Quantum Relief extension in the client hello enables the client
 * to negotiate a hardening mechanism against quantum computers with the
 * server.
 *
 * This module implements the Kerberised Diffie-Hellman (KDH) quantum
 * relief method.
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

#ifndef QUANTUM_RELIEF_KDH_H
#define QUANTUM_RELIEF_KDH_H

#ifdef __cplusplus
extern "C" {
#endif

int mbedtls_qr_init_kdh( mbedtls_ssl_context *ssl,
                         unsigned char *buf,
                         unsigned char *end,
                         size_t *out_len );

int mbedtls_qr_proc_kdh_server( mbedtls_ssl_context *ssl,
                                const unsigned char *buf,
                                const unsigned char *end );

int mbedtls_qr_confirm_kdh( mbedtls_ssl_context *ssl,
                            unsigned char *buf,
                            unsigned char *end,
                            size_t *out_len );

int mbedtls_qr_proc_kdh_client( mbedtls_ssl_context *ssl,
                                const unsigned char *buf,
                                const unsigned char *end );

#ifdef __cplusplus
}
#endif

#endif /* QUANTUM_RELIEF_KDH_H */
