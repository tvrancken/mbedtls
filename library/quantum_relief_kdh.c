/*
 *  Quantum Relief method Kerberized Diffie-Hellman (KDH)
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
#if defined(MBEDTLS_QR_METHOD_KDH_C)


#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/version.h"
#include "mbedtls/quantum_relief.h"

#include "ssl_debug_helpers.h"

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


/*** Quantum Relief KDH function definitions ***/
/* Note:
 * To improve readability, the functions are ordered such that they
 * follow the TLS handshake flow.
 *
 * init_qr_kdh() -> in Client Hello
 * proc_qr_kdh_server() -> on server
 * confirm_qr_kdh() -> in Server Hello
 * proc_qr_kdh_client() -> on client
 */

/* Kerberized Diffie-Hellman
 *
 * Message structure:
 * < qr_method ++ krb_ticket ++ peer_name_type ++ peer_name >
 * with lengths
 * < 16 bits ++ 16 bits + len(ticket) ++ 16 bits ++ 16 bits + len(pnt) >
 **/
int mbedtls_qr_init_kdh( mbedtls_ssl_context *ssl,
                         unsigned char *buf,
                         unsigned char *end,
                         size_t *out_len )
{
    int ret;
    mbedtls_certificate_credentials_t cred;
    mbedtls_peer_name_type_t peer_name_type;
    mbedtls_datum_t peer_name;
    struct mbedtls_cert_retr_st info;
    mbedtls_pk_algorithm_t pk_algos = { MBEDTLS_PK_KDH };
    /* Variables to be filled via callback */
    mbedtls_pcert_st* pcert = NULL; // shall contain the ticket
    unsigned int pcert_length = 0;
    unsigned int flags = 0;
    /* Variables that can be filled via callback but will be ignored */
    mbedtls_ocsp_data_st* ocsp = NULL;
    unsigned int ocsp_length = 0;
    mbedtls_privkey_t pkey = NULL;


    /* Only activate this mechanism if alternative cert types are allowed,
     * Kerberos certificates are enabled, and we have cert credentials set.
     */
    if (!are_alternative_cert_types_allowed(ssl) ||
       (!is_cert_type_enabled(ssl, MBEDTLS_SSL_CERT_TYPE_KRB)) ||
       ((cred = (gnutls_certificate_credentials_t)_gnutls_get_cred(ssl, MBEDTLS_CRD_CERTIFICATE)) == NULL)) {
        MBEDTLS_SSL_DEBUG_MSG("EXT[%p]: Kerberos credentials are not allowed or not set. "
                 "We therefore do not propose this method.\n", ssl);

        return 0; // Bytes
    }

    MBEDTLS_SSL_DEBUG_MSG("EXT[%p]: Preparing Quantum Relief method based on kerberized Diffie-Hellman (KDH).\n", ssl);

    /* Get the Kerberos ticket
     * We only support ticket retrieval via a callback mechanism (at least for now).
     * Pre set credentials cannot be used. TODO: explain why?
     *
     * A ticket is either a regular ticket or a ticket granting ticket (TGT). One
     * of these MUST be retrieved in order to proceed.
     *
     * If there is a callback set, use it. Otherwise, error.
     */
    if (cred->get_cert_callback3) {
        // Set info structure
        memset(&info, 0, sizeof(info));
        info.req_ca_rdn = NULL; // Not relevant
        info.nreqs = 0;
        info.pk_algos = &pk_algos;
        info.pk_algos_length = 1;
        info.cred = cred;

        MBEDTLS_SSL_DEBUG_MSG("EXT[%p]: Making callback to retrieve Krb ticket.\n", ssl);

        // Make the callback
        ret = cred->get_cert_callback3(ssl, &info, &pcert, &pcert_length,
                                       &ocsp, &ocsp_length, &pkey, &flags);
        if (ret < 0) {
            return mbedtls_assert_val(MBEDTLS_E_USER_ERROR);
        }

        // Sanity checks
        if (pcert_length == 0 || pcert == NULL ||
           (pcert_length > 0 && pcert[0].type != MBEDTLS_SSL_CERT_TYPE_KRB)) {
            //TODO: log?
            return mbedtls_assert_val(MBEDTLS_E_INVALID_REQUEST);
        }

        // Cache the ticket for later use (i.e., entropy retrieval)
        _mbedtls_hello_ext_set_datum(ssl, MBEDTLS_EXTENSION_QUANTUM_RELIEF, &pcert->cert);

        //TODO: check for pcert_length > 1? Is het erg als we er meer krijgen?  We kunnen de rest negeren.

    } else {
        MBEDTLS_SSL_DEBUG_MSG("EXT[%p]: No certificate retrieval callback set. "
                 "We can't retrieve the required Kerberos ticket. Aborting with error.\n", ssl);
        return mbedtls_assert_val(MBEDTLS_E_USER_ERROR);
    }

    /* Get the peer name type and peer name set */
    peer_name_type = ssl->internals.qr_peer_name_type; // TODO implement getter?
    peer_name = ssl->internals.qr_peer_name; //TODO idem

    /* Generate the extension data */
    // 1) Append the QR method to the buffer
    ret = append_qr_method(data, MBEDTLS_QR_METHOD_KDH);

    if (ret < 0) {
        return mbedtls_assert_val(ret);
    }

    // 2) Append the Krb ticket to the buffer
    ret = _mbedtls_buffer_append_data_prefix(data, 16, pcert->cert.data, pcert->cert.size);

    if (ret < 0) {
        return mbedtls_assert_val(ret);
    }

    // 3) Append the peer name type to the buffer
    ret = append_peer_name_type(data, peer_name_type);

    if (ret < 0) {
        return mbedtls_assert_val(ret);
    }

    // 4) Append the peer name to the buffer (in case it is set)
    if (peer_name_type != MBEDTLS_PNT_NONE) {
        ret = _mbedtls_buffer_append_data_prefix(data, 16, peer_name.data, peer_name.size);

        if (ret < 0) {
            return mbedtls_assert_val(ret);
        }
    }

    MBEDTLS_SSL_DEBUG_MSG("EXT[%p]: Finished preparing Quantum Relief method based on kerberized Diffie-Hellman (KDH).\n", ssl);

    return data->length; // Bytes
}

int mbedtls_qr_proc_kdh_server( mbedtls_ssl_context *ssl,
                                const unsigned char *buf,
                                const unsigned char *end )
{
    int ret = 0;
    mbedtls_certificate_credentials_t cred;
    mbedtls_datum_t received_ticket;
    uint16_t received_ticket_size;
    mbedtls_peer_name_type_t peer_name_type;
    mbedtls_datum_t retrieved_entropy;

    /* Only activate this mechanism if alternative cert types are allowed,
     * Kerberos certificates are enabled, and we have cert credentials set.
     */
    if (!are_alternative_cert_types_allowed(ssl) ||
       (!is_cert_type_enabled(ssl, MBEDTLS_SSL_CERT_TYPE_KRB)) ||
       ((cred = (mbedtls_certificate_credentials_t)_mbedtls_get_cred(ssl, MBEDTLS_CRD_CERTIFICATE)) == NULL)) {
        MBEDTLS_SSL_DEBUG_MSG("EXT[%p]: Kerberos credentials are not allowed or not set. "
                 "We therefore do not accept this method.\n", ssl);

        return 0; // TODO what is this? Bytes or status?
    }

    MBEDTLS_SSL_DEBUG_MSG("EXT[%p]: Processing Quantum Relief method based on kerberized Diffie-Hellman (KDH).\n", ssl);

    /* Read the length of our ticket (or TGT). Our message chunk looks like: TODO comment properly
     * <length++ticket> where
     * length = 2 bytes and
     * ticket = length bytes.
     */
    DECR_LEN(data_size, 2);
    received_ticket_size = _mbedtls_read_uint16(data);
    data += 2;

    if (received_ticket_size == 0) {
        return mbedtls_assert_val(MBEDTLS_E_UNEXPECTED_PACKET_LENGTH); //TODO check error code
    }

    MBEDTLS_SSL_DEBUG_MSG("EXT[%p]: Reading Krb ticket or TGT of size %d bytes. \n", ssl, received_ticket_size);

    DECR_LEN(data_size, received_ticket_size);
    ret = _mbedtls_set_datum(&received_ticket, data, received_ticket_size);

    if (ret < 0) {
        return mbedtls_assert_val(ret);
    }

    data += received_ticket_size;

    /* Read the peer name type */
    ret = read_peer_name_type(&data, &data_size, &peer_name_type);

    if (ret < 0) {
        return mbedtls_assert_val(ret);
    }

    /* Set the peer name type for this session */
    ssl->internals.qr_peer_name_type = peer_name_type; //TODO create setter?

    /* Determine remaining processing flow based on the received peer name type */
    switch (peer_name_type) {
        case MBEDTLS_PNT_NONE: // Regular client-server flow
            /* Validate the msg format: the remainder should be empty. */
            if (data_size != 0) {
                return mbedtls_assert_val(MBEDTLS_E_UNEXPECTED_PACKET_LENGTH);
            }

            // Try to retrieve the entropy from the ticket
            if (cred->krb_entropy_retrieval_callback == NULL) {
                MBEDTLS_SSL_DEBUG_MSG("EXT[%p]: No entropy retrieval callback set. "
                    "We can't retrieve the required entropy from the Kerberos ticket. Aborting with error.\n", ssl);
                return mbedtls_assert_val(MBEDTLS_E_USER_ERROR);
            }

            MBEDTLS_SSL_DEBUG_MSG("EXT[%p]: Making callback to retrieve entropy.\n", ssl);

            ret = cred->krb_entropy_retrieval_callback(ssl, &received_ticket, &retrieved_entropy);

            if (ret < 0) {
                mbedtls_assert_val(MBEDTLS_E_USER_ERROR);
            }

            /* At this point we have succesfully processed the QR KDH method
             * and retrieved the required entropy. We now insert this entropy
             * in the TLS key schedule.
             */
            ret = inject_entropy(ssl, retrieved_entropy);

            if (ret < 0) {
                return mbedtls_assert_val(ret);
            }

            ssl->security_parameters.qr_method = MBEDTLS_QR_METHOD_KDH; //TODO like this or with function? eg _mbedtls_session_client_cert_type_set()
            ssl->internals.hsk_flags |= HSK_QR_SELECTED; //TODO check correct position
            // TODO when we receive this ext confirm use of KDH and store this / set a flag? do we need more than the above?

            MBEDTLS_SSL_DEBUG_MSG("EXT[%p]: Successfully performed KDH-based Quantum Relief.\n ", ssl);

            return 0;
        case MBEDTLS_PNT_KRB5PRINCREALM: // p2p flow
            //TODO implement
            // read / parse peer name type value
            return mbedtls_assert_val(MBEDTLS_E_UNIMPLEMENTED_FEATURE);
        default:
            return mbedtls_assert_val(MBEDTLS_E_INVALID_REQUEST); //TODO check error code
    }
}

int mbedtls_qr_confirm_kdh( mbedtls_ssl_context *ssl,
                            unsigned char *buf,
                            unsigned char *end,
                            size_t *out_len )
{
    int ret;
    mbedtls_peer_name_type_t peer_name_type;

    /* This should only run on a server */
    assert(IS_SERVER(ssl));

    /* Verify that we indeed successfully received and executed a QR KDH request */
    if (!(ssl->security_parameters.qr_method == MBEDTLS_QR_METHOD_KDH &&
          ssl->internals.hsk_flags & HSK_QR_SELECTED)) {
        return 0; // Bytes
    }

    MBEDTLS_SSL_DEBUG_MSG("EXT[%p]: Preparing response for Quantum Relief method based on kerberized Diffie-Hellman (KDH).\n", ssl);

    /* Get the requested peer name type */
    peer_name_type = ssl->internals.qr_peer_name_type; //TODO use getter?

    /* Generate a response to confirm the proposed QR params by the client */
    // 1) Append the QR method to the buffer
    ret = append_qr_method(data, MBEDTLS_QR_METHOD_KDH);

    if (ret < 0) {
        return mbedtls_assert_val(ret);
    }

    // 2) Append the Krb ticket to the buffer (can be empty).
    switch (peer_name_type) {
        case MBEDTLS_PNT_NONE:
            // We will return no ticket. We indicate this by sending a 16 bit length prefix with value 0
            ret = _mbedtls_buffer_append_prefix(data, 16, 0);

            if (ret < 0) {
                return mbedtls_assert_val(ret);
            }

            break;
        case MBEDTLS_PNT_KRB5PRINCREALM:
            // TODO implement
            /*ret = _mbedtls_buffer_append_data_prefix(data, 16, pcert->cert.data, pcert->cert.size);

            if (ret < 0) {
                return mbedtls_assert_val(ret);
            }*/
            return mbedtls_assert_val(MBEDTLS_E_UNIMPLEMENTED_FEATURE);
        default:
            return mbedtls_assert_val(MBEDTLS_E_INVALID_REQUEST);
    }

    // 3) Append the peer name type to the buffer (for confirmation purposes)
    ret = append_peer_name_type(data, peer_name_type);

    if (ret < 0) {
        return mbedtls_assert_val(ret);
    }

    // Note: there will never be a peer name specified for server to client communication

    MBEDTLS_SSL_DEBUG_MSG("EXT[%p]: Finished creating response message for Quantum Relief method based on kerberized Diffie-Hellman (KDH).\n", ssl);

    return data->length; // Bytes
}

int mbedtls_qr_proc_kdh_client( mbedtls_ssl_context *ssl,
                                const unsigned char *buf,
                                const unsigned char *end )
{
    int ret = 0;
    mbedtls_certificate_credentials_t cred;
    mbedtls_datum_t received_ticket;
    uint16_t received_ticket_size;
    mbedtls_datum_t cached_ticket;
    mbedtls_peer_name_type_t peer_name_type;
    mbedtls_datum_t retrieved_entropy;

    /* Precondition:
     * Alternative cert types are allowed, Kerberos certificates are enabled,
     * and we have cert credentials set.
     * This was already checked during the KDH initialization routine (init_qr_kdh).
     */
    cred = (mbedtls_certificate_credentials_t)_mbedtls_get_cred(ssl, MBEDTLS_CRD_CERTIFICATE);

    MBEDTLS_SSL_DEBUG_MSG("EXT[%p]: Processing Quantum Relief method based on kerberized Diffie-Hellman (KDH).\n", ssl);

    /* Read the length of our ticket (or TGT). Our message chunk looks like: TODO comment properly
     * <length++ticket> where
     * length = 2 bytes and
     * ticket = length bytes.
     */
    DECR_LEN(data_size, 2);
    received_ticket_size = _mbedtls_read_uint16(data);
    data += 2;

    if (received_ticket_size > 0) {
        MBEDTLS_SSL_DEBUG_MSG("EXT[%p]: Reading Krb ticket or TGT of size %d bytes. \n", ssl, received_ticket_size);

        DECR_LEN(data_size, received_ticket_size);
        ret = _mbedtls_set_datum(&received_ticket, data, received_ticket_size);

        if (ret < 0) {
            return mbedtls_assert_val(ret);
        }

        data += received_ticket_size;
    }

    /* Read the peer name type */
    ret = read_peer_name_type(&data, &data_size, &peer_name_type);

    if (ret < 0) {
        return mbedtls_assert_val(ret);
    }

    /* Sanity check: check whether the confirmed peer name type matches the one that we requested */
    if (ssl->internals.qr_peer_name_type != peer_name_type) {
        return mbedtls_assert_val(MBEDTLS_E_INVALID_REQUEST); //TODO check error code
    }

    /* Sanity check: check whether the remaining message is empty */
    if (data_size != 0) {
        return mbedtls_assert_val(MBEDTLS_E_UNEXPECTED_PACKET_LENGTH);
    }

    /* Determine remaining processing flow based on the received peer name type */
    switch (peer_name_type) {
        case MBEDTLS_PNT_NONE: // Regular client-server flow
            /* Sanity check: we should not have received a ticket from the server */
            if (received_ticket_size > 0) {
                //TODO log
                return mbedtls_assert_val(MBEDTLS_E_INVALID_REQUEST);
            }

            /* Retrieve our cached ticket */
            ret = _mbedtls_hello_ext_get_datum(ssl, MBEDTLS_EXTENSION_QUANTUM_RELIEF, &cached_ticket);

            if (ret < 0) {
                mbedtls_assert_val(ret);
            }

            /* Try to retrieve the entropy from the cached ticket */
            if (cred->krb_entropy_retrieval_callback == NULL) {
                MBEDTLS_SSL_DEBUG_MSG("EXT[%p]: No entropy retrieval callback set. "
                    "We can't retrieve the required entropy from the Kerberos ticket. Aborting with error.\n", ssl);
                return mbedtls_assert_val(MBEDTLS_E_USER_ERROR);
            }

            MBEDTLS_SSL_DEBUG_MSG("EXT[%p]: Making callback to retrieve entropy.\n", ssl);

            ret = cred->krb_entropy_retrieval_callback(ssl, &cached_ticket, &retrieved_entropy);

            if (ret < 0) {
                mbedtls_assert_val(MBEDTLS_E_USER_ERROR);
            }

            /* At this point we have succesfully processed the QR KDH method
             * and retrieved the required entropy. We now insert this entropy
             * in the TLS key schedule.
             */
            ret = inject_entropy(ssl, retrieved_entropy);

            if (ret < 0) {
                return mbedtls_assert_val(ret);
            }

            ssl->security_parameters.qr_method = MBEDTLS_QR_METHOD_KDH; //TODO like this or with function? eg _mbedtls_ssl_client_cert_type_set()
            ssl->internals.hsk_flags |= HSK_QR_SELECTED; //TODO check correct position
            // TODO when we receive this ext confirm use of KDH and store this / set a flag? do we need more than the above?

            MBEDTLS_SSL_DEBUG_MSG("EXT[%p]: Successfully performed KDH-based Quantum Relief.\n ", ssl);

            return 0;
        case MBEDTLS_PNT_KRB5PRINCREALM: // p2p flow
            //TODO implement
            return mbedtls_assert_val(MBEDTLS_E_UNIMPLEMENTED_FEATURE);
        default:
            return mbedtls_assert_val(MBEDTLS_E_INVALID_REQUEST); //TODO check error code
    }
}

/*** Public functions and APIs ***/


#endif /* MBEDTLS_QR_METHOD_KDH_C */
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
#endif /* MBEDTLS_QUANTUM_RELIEF_C */
