/*
 * FILE: packet.c
 * Containing community specific packet handling instrumentation.
 */

#include <config.h>

#include <stdio.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <sys/types.h>

#include "asn1.h"
#include "snmp.h"
#include "snmp_api.h"
#include "snmp_debug.h"
#include "tools.h"
#include "default_store.h"

#include "community/snmp_community.h"

int netsnmp_community_build(u_char **pkt, size_t *pkt_len, size_t *offset,
            struct snmp_session *session, struct snmp_pdu *pdu)
{
     u_char *h0, *h0e = 0, *h1;
     u_char *cp;
     size_t length, start_offset = *offset;
     long version;
     int rc = 0;


    switch (pdu->command) {
        case SNMP_MSG_RESPONSE:
            pdu->flags &= (~UCD_MSG_FLAG_EXPECT_RESPONSE);
                /* Fallthrough */
        case SNMP_MSG_GET:
        case SNMP_MSG_GETNEXT:
        case SNMP_MSG_SET:
            /* all versions support these PDU types */
            /* initialize defaulted PDU fields */

            if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
                pdu->errstat = 0;
            if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
                pdu->errindex = 0;
            break;

        case SNMP_MSG_TRAP2:
            pdu->flags &= (~UCD_MSG_FLAG_EXPECT_RESPONSE);
                /* Fallthrough */
        case SNMP_MSG_INFORM:
            /* not supported in SNMPv1 and SNMPsec */
            if (pdu->version == SNMP_VERSION_1) {
                    session->s_snmp_errno = SNMPERR_V2_IN_V1;
                    return -1;
            }
            if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
                pdu->errstat = 0;
            if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
                pdu->errindex = 0;
            break;

        case SNMP_MSG_GETBULK:
            /* not supported in SNMPv1 and SNMPsec */
            if (pdu->version == SNMP_VERSION_1) {
                    session->s_snmp_errno = SNMPERR_V2_IN_V1;
                    return -1;
            }
            if (pdu->max_repetitions < 0) {
                session->s_snmp_errno = SNMPERR_BAD_REPETITIONS;
                return -1;
            }
            if (pdu->non_repeaters < 0) {
                session->s_snmp_errno = SNMPERR_BAD_REPEATERS;
                return -1;
            }
            break;

        case SNMP_MSG_TRAP:
            /* *only* supported in SNMPv1 and SNMPsec */
            if (pdu->version != SNMP_VERSION_1) {
                    session->s_snmp_errno = SNMPERR_V1_IN_V2;
                    return -1;
            }
            /* initialize defaulted Trap PDU fields */
            pdu->reqid = 1;     /* give a bogus non-error reqid for traps */
            if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
                pdu->enterprise = (oid *)malloc(default_enterprise_length);
                if (pdu->enterprise == NULL) {
                    session->s_snmp_errno = SNMPERR_MALLOC;
                    return -1;
                }
                memmove(pdu->enterprise, DEFAULT_ENTERPRISE,
                    default_enterprise_length);
                pdu->enterprise_length = default_enterprise_length/sizeof(oid);
            }
            if (pdu->time == SNMP_DEFAULT_TIME)
                pdu->time = DEFAULT_TIME;
            /* don't expect a response */
            pdu->flags &= (~UCD_MSG_FLAG_EXPECT_RESPONSE);
            break;

        case SNMP_MSG_REPORT:           /* SNMPv3 only */
        default:
            session->s_snmp_errno = SNMPERR_UNKNOWN_PDU;
            return -1;
    }

    /* save length */
    length = *pkt_len;

    /* setup administrative fields based on version */
    /* build the message wrapper and all the administrative fields
       upto the PDU sequence
       (note that actual length of message will be inserted later) */
    h0 = *pkt;

#ifdef NO_ZEROLENGTH_COMMUNITY
    if (pdu->community_len == 0) {
        if (session->community_len == 0) {
            session->s_snmp_errno = SNMPERR_BAD_COMMUNITY;
            return -1;
        }
        pdu->community = (u_char *)malloc(session->community_len);
        if (pdu->community == NULL) {
            session->s_snmp_errno = SNMPERR_MALLOC;
            return -1;
        }
        memmove(pdu->community,
                session->community, session->community_len);
        pdu->community_len = session->community_len;
    }
#else /* !NO_ZEROLENGTH_COMMUNITY */
    if (pdu->community_len == 0 && pdu->command != SNMP_MSG_RESPONSE) {
        /* copy session community exactly to pdu community */
        if (0 == session->community_len) {
            SNMP_FREE(pdu->community);
            pdu->community = NULL;
        } else if (pdu->community_len == session->community_len) {
            memmove(pdu->community,
                    session->community, session->community_len);
        } else {
            SNMP_FREE(pdu->community);
            pdu->community = (u_char *)malloc(session->community_len);
            if (pdu->community == NULL) {
                session->s_snmp_errno = SNMPERR_MALLOC;
                return -1;
            }
            memmove(pdu->community,
                    session->community, session->community_len);
        }
        pdu->community_len = session->community_len;
    }
#endif /* !NO_ZEROLENGTH_COMMUNITY */

    DEBUGMSGTL(("snmp_send", "Building SNMPv%d message...\n",
                    (1 + pdu->version)));

#ifdef USE_REVERSE_ASNENCODING
    if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_REVERSE_ENCODE)) {
        DEBUGPRINTPDUTYPE("send", pdu->command);
        rc = snmp_pdu_realloc_rbuild(pkt, pkt_len, offset, pdu);
        if (rc == 0) {
          return -1;
        }

        DEBUGDUMPHEADER("send", "Community String");
        rc = asn_realloc_rbuild_string(pkt, pkt_len, offset, 1,
                   (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
                   pdu->community, pdu->community_len);
        DEBUGINDENTLESS();
        if (rc == 0) {
          return -1;
        }


        /*  Store the version field.  */
        DEBUGDUMPHEADER("send", "SNMP Version Number");

        version = pdu->version;
        rc = asn_realloc_rbuild_int(pkt, pkt_len, offset, 1,
                     (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                     (long *)&version, sizeof(version));
        DEBUGINDENTLESS();
        if (rc == 0) {
          return -1;
        }

        /*  Build the final sequence.  */
        if (pdu->version == SNMP_VERSION_1) {
          DEBUGDUMPSECTION("send", "SNMPv1 Message");
        } else {
          DEBUGDUMPSECTION("send", "SNMPv2c Message");
        }
        rc = asn_realloc_rbuild_sequence(pkt, pkt_len, offset, 1,
                                  (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
                                  *offset - start_offset);

        if (rc == 0) {
          return -1;
        }
        return 0;

   } else {

#endif /* USE_REVERSE_ASNENCODING */
        /* Save current location and build SEQUENCE tag and length
           placeholder for SNMP message sequence
           (actual length will be inserted later) */
        cp = asn_build_sequence(*pkt, pkt_len,
                                (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
                                0);
        if (cp == NULL) {
            return -1;
        }
        h0e = cp;

        if (pdu->version == SNMP_VERSION_1) {
            DEBUGDUMPSECTION("send", "SNMPv1 Message");
        } else {
            DEBUGDUMPSECTION("send", "SNMPv2c Message");
        }

        /* store the version field */
        DEBUGDUMPHEADER("send", "SNMP Version Number");

        version = pdu->version;
        cp = asn_build_int(*pkt, pkt_len,
                     (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                     (long *)&version, sizeof(version));
        DEBUGINDENTLESS();
        if (cp == NULL)
            return -1;

        /* store the community string */
        DEBUGDUMPHEADER("send", "Community String");
        cp = asn_build_string(*pkt, pkt_len,
                   (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
                   pdu->community, pdu->community_len);
        DEBUGINDENTLESS();
        if (cp == NULL)
            return -1;
#ifdef USE_REVERSE_ASNENCODING
        }
#endif /* USE_REVERSE_ASNENCODING */

    h1 = cp;
    DEBUGPRINTPDUTYPE("send", pdu->command);
    cp = snmp_pdu_build(pdu, cp, pkt_len);
    DEBUGINDENTADD(-4); /* return from entire v1/v2c message */
    if (cp == NULL)
        return -1;

    asn_build_sequence(*pkt, &length,
                       (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
                       cp - h0e);

    *pkt_len = cp - *pkt;
    return 0;
}
