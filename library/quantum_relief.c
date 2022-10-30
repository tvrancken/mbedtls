/*
 *  Quantum Relief extension
 *
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
/*
 *  https://datatracker.ietf.org/doc/html/draft-vanrein-tls-kdh
 *  This module works only with TLS 1.3
 */

#include "common.h"

#if defined(MBEDTLS_QUANTUM_RELIEF_C)
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/version.h"
#include "mbedtls/quantum_relief.h"

#include "quantum_relief_kdh.h"
#include "ssl_debug_helpers.h"


/*** Specific Quantum Relief method handling ***/
/* The implementation of specific quantum relief methods should be
 * placed in separate C modules to improve modularity and readability.
 */

/*** Stuff for testing ***/
#if defined(MBEDTLS_TEST_HOOKS)
static mbedtls_ssl_chk_buf_ptr_args chk_buf_ptr_fail_args;

void mbedtls_ssl_set_chk_buf_ptr_fail_args(
    const uint8_t *cur, const uint8_t *end, size_t need )
{
    chk_buf_ptr_fail_args.cur = cur;
    chk_buf_ptr_fail_args.end = end;
    chk_buf_ptr_fail_args.need = need;
}

void mbedtls_ssl_reset_chk_buf_ptr_fail_args( void )
{
    memset( &chk_buf_ptr_fail_args, 0, sizeof( chk_buf_ptr_fail_args ) );
}

int mbedtls_ssl_cmp_chk_buf_ptr_fail_args( mbedtls_ssl_chk_buf_ptr_args *args )
{
    return( ( chk_buf_ptr_fail_args.cur  != args->cur  ) ||
            ( chk_buf_ptr_fail_args.end  != args->end  ) ||
            ( chk_buf_ptr_fail_args.need != args->need ) );
}
#endif /* MBEDTLS_TEST_HOOKS */


/*** TLS extension function definitions ***/
/* mbedtls_ssl_write_quantum_relief_ext()
 *
 * Write Quantum Relief extension data in Client Hello and Server Hello messages.
 * Used to negotiate a quantum relief method. See include/mbedtls/quantum_relief.h
 * for supported QR methods.
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_write_quantum_relief_ext( mbedtls_ssl_context *ssl,
                                          unsigned char *buf,
                                          unsigned char *end,
                                          size_t *out_len )
{
    /* Don't enable QR if PSK is also enabled, they are incompatible. */
    if( mbedtls_ssl_conf_tls13_some_psk_enabled( ssl ) ) {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "Detected that PSK key exchanges are enabled. "
                                    "Quantum Relief and PSK are mutually exclusive. Aborting...\n" ) );

        return( MBEDTLS_ERR_QR_INCOMPATIBLE_EXTENSION );
    }

    /* By default we send nothing */
    *out_len = 0;

    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT ) {
        /* Client mode:
         * Call the right QR method handler based on the configured
         * QR method.
         */
        switch( ssl->conf->qr_method ) {
            case MBEDTLS_QR_METHOD_NONE:
                /* We don't send this extension.
                 * This is according to spec.
                 */
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "Quantum Relief method was set to 'None'. "
                                            "Therefore, we don't send this extension." ) );
                return( 0 );
#if defined(MBEDTLS_QR_METHOD_KDH_C)
            case MBEDTLS_QR_METHOD_KDH:
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "Received instructions to propose a Quantum Relief method "
                                            "based on kerberized Diffie-Hellman (KDH)." ) );

                return mbedtls_qr_init_kdh( ssl, buf, end, out_len );
#endif /* MBEDTLS_QR_METHOD_KDH_C */
            default:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "Unkown Quantum Relief method specified. "
                                            "Therefore, we don't send this extension. "
                                            "Please check your configuration." ) );
                return( 0 );
        }

    } else {
        /* Server mode:
         * If we agreed to perform a certain QR method (decided upon reception
         * of the Client Hello extension), we call the right QR handler here
         * to generate our response to the client.
         */
        if( !(ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_QUANTUM_RELIEF) ) {
            MBEDTLS_SSL_DEBUG_MSG( 3, ( "server hello, don't send quantum_relief extension "
                                        "because we didn't receive it from the client." ) );

            return( 0 );
        }

        switch( ssl->session_negotiate->qr_method ) {
#if defined(MBEDTLS_QR_METHOD_KDH_C)
            case MBEDTLS_QR_METHOD_KDH:
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "Confirming Quantum Relief method based on "
                                            "kerberized Diffie-Hellman (KDH)." ) );

                return mbedtls_qr_confirm_kdh( ssl, buf, end, out_len );
#endif /* MBEDTLS_QR_METHOD_KDH_C */
            case MBEDTLS_QR_METHOD_NONE:
                /* Should not happen since the client is not allowed to
                 * advertise method None according to spec. */
            default:
                /* Illegal state, should not happen!
                 * Apparently, we negotiated an unkown QR method or the
                 * client advertised the None method. Either way, we should
                 * terminate the connection as this signals non compliance. */
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
    }
}

/* mbedtls_ssl_write_quantum_relief_ext()
 *
 * Parse Quantum Relief extension data on reception of Client Hello
 * and Server Hello messages. Used to negotiate a quantum relief method.
 * See include/mbedtls/quantum_relief.h for supported QR methods.
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_parse_quantum_relief_ext( mbedtls_ssl_context *ssl,
                                          const unsigned char *buf,
                                          const unsigned char *end )
{
    mbedtls_qr_method_t qr_method;

    /* Read the QR method
     * The extension header is already chopped off here.
     * We only need to read the rest of our message:
     *
     * - qr_method (2 bytes)
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( buf, end, 2 );

    qr_method = MBEDTLS_GET_UINT16_BE( buf, 0 );

    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER ) {
        /* Server mode:
         * We receive a QR method that the client proposes to perform.
         * We read the proposal and check whether we support it.
         */

        switch( qr_method ) {
#if defined(MBEDTLS_QR_METHOD_KDH_C)
            case MBEDTLS_QR_METHOD_KDH:
                MBEDTLS_SSL_DEBUG_MSG( 1, (" Received Quantum Relief method request based on kerberized Diffie-Hellman (KDH). ") );

                return mbedtls_qr_proc_kdh_server( ssl, buf, end );
#endif /* MBEDTLS_QR_METHOD_KDH_C */
            case MBEDTLS_QR_METHOD_NONE:
                /* Illegal value. The client is not supposed to advertise
                 * QR method 'None'.
                 */
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "Received a Quantum Relief method 'None'. "
                                            "This value is not supposed to be advertised by a client." ) );

                return( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE );
            default:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "Received an unknown Quantum Relief method request." ) );

                return( MBEDTLS_ERR_QR_UNKOWN_METHOD_REQUESTED );
        }
    } else {
        /* Client mode:
         * We receive a QR method confirmation from the server and
         * handle it accordingly.
         */

        /* Sanity check: verify whether the confirmed mechanism matches
         * the proposed mechanism.
         */
        if( ssl->conf->qr_method != qr_method ) {
            return( MBEDTLS_ERR_QR_ILLEGAL_METHOD_REQUESTED );
        }

        switch( qr_method ) {
#if defined(MBEDTLS_QR_METHOD_KDH_C)
            case MBEDTLS_QR_METHOD_KDH:
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "Received Quantum Relief method confirmation for kerberized Diffie-Hellman (KDH)." ) );

                return mbedtls_qr_proc_kdh_client( ssl, buf, end );
#endif /* MBEDTLS_QR_METHOD_KDH_C */
            case MBEDTLS_QR_METHOD_NONE:
                /* Illegal state. The server is not supposed to
                 * confirm a 'None' method since we (as client) are
                 * not supposed to advertise it in the first place.
                 */
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "Received confirmation for Quantum Relief method 'None'. "
                                            "This value is not supposed to be confirmed by a server." ) );

                return( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE );
            default:
                /* Illegal state. The server confirmed a method that
                 * we don't know. This cannot happen since we only
                 * advertise methods that we know and are able to perform.
                 */
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "Received confirmation for an unkown Quantum Relief method. "
                                            "This looks like an imcompliant server." ) );

                return( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE );
        }
    }
}

/*** Public functions and APIs ***/
/* Configure the QR method to propose to the server */
int mbedtls_ssl_conf_qr_method( mbedtls_ssl_config* conf, mbedtls_qr_method_t qr_method )
{
    if( conf->endpoint == MBEDTLS_SSL_IS_SERVER ) {
        return( MBEDTLS_ERR_SSL_BAD_CONFIG );
    }

    conf->qr_method = qr_method;

    return 0;
}

#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
#endif /* MBEDTLS_QUANTUM_RELIEF_C */
