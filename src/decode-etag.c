/* Copyright (C) 2025 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \ingroup decode
 *
 * @{
 */

/**
 * \file
 *
 * \author Fupeng Zhao <fupeng.zhao@foxmail.com>
 *
 * Decode ETag 802.1BR
 */

#include "suricata-common.h"
#include "decode-etag.h"
#include "decode.h"
#include "decode-events.h"

#include "util-validate.h"
#include "util-unittest.h"
#include "util-debug.h"

/**
 * \internal
 * \brief this function is used to decode 802.1BR packets
 *
 * \param tv pointer to the thread vars
 * \param dtv pointer code thread vars
 * \param p pointer to the packet struct
 * \param pkt pointer to the raw packet
 * \param len packet len
 *
 */
int DecodeETAG(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, const uint8_t *pkt, uint32_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    StatsIncr(tv, dtv->counter_etag);

    if (len < ETAG_HEADER_LEN) {
        ENGINE_SET_INVALID_EVENT(p, ETAG_HEADER_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }

    EtagHdr *etag_hdr = (EtagHdr *)pkt;

    uint16_t proto = GET_ETAG_PROTO(etag_hdr);

    if (DecodeNetworkLayer(tv, dtv, proto, p, pkt + ETAG_HEADER_LEN, len - ETAG_HEADER_LEN) ==
            false) {
        ENGINE_SET_INVALID_EVENT(p, ETAG_UNKNOWN_TYPE);
        return TM_ECODE_FAILED;
    }
    return TM_ECODE_OK;
}

#ifdef UNITTESTS
#include "util-unittest-helper.h"
#include "packet.h"

/**
 * \test DecodeETAGTest01 test if etag header is too small.
 *
 */
static int DecodeETAGTest01(void)
{
    uint8_t raw_etag[] = { 0x00, 0x20, 0x08 };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);

    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FAIL_IF(TM_ECODE_OK == DecodeETAG(&tv, &dtv, p, raw_etag, sizeof(raw_etag)));

    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, ETAG_HEADER_TOO_SMALL));
    PacketFree(p);
    PASS;
}

/**
 * \test DecodeETAGTest02 test if etag header has unknown type.
 *
 */
static int DecodeETAGTest02(void)
{
    uint8_t raw_etag[] = { 0x10, 0x00, 0x00, 0xd3, 0xff, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x28,
        0x61, 0xcb, 0x40, 0x00, 0x40, 0x06, 0x2b, 0xbd, 0x34, 0x72, 0x7c, 0x6a, 0xc0, 0xa8, 0x01,
        0x2e, 0x01, 0xbb, 0xcd, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
        0x20, 0x00, 0x3a, 0x70, 0x00, 0x00 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FAIL_IF_NOT(TM_ECODE_OK != DecodeETAG(&tv, &dtv, p, raw_etag, sizeof(raw_etag)));
    PacketFree(p);
    PASS;
}

/**
 * \test DecodeETAGTest03 test a good etag header.
 *
 */
static int DecodeETAGTest03(void)
{
    uint8_t raw_etag[] = { 0x10, 0x00, 0x00, 0xd3, 0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x61, 0xcb,
        0x40, 0x00, 0x40, 0x06, 0x2b, 0xbd, 0x34, 0x72, 0x7c, 0x6a, 0xc0, 0xa8, 0x01, 0x2e, 0x01,
        0xbb, 0xcd, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00,
        0x3a, 0x70, 0x00, 0x00 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);

    ThreadVars tv = { 0 };
    DecodeThreadVars dtv = { 0 };

    FlowInitConfig(FLOW_QUIET);

    FAIL_IF(TM_ECODE_OK != DecodeETAG(&tv, &dtv, p, raw_etag, sizeof(raw_etag)));

    PacketRecycle(p);
    FlowShutdown();
    PacketFree(p);
    PASS;
}
#endif /* UNITTESTS */

void DecodeETAGRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeETAGTest01", DecodeETAGTest01);
    UtRegisterTest("DecodeETAGTest02", DecodeETAGTest02);
    UtRegisterTest("DecodeETAGTest03", DecodeETAGTest03);
#endif /* UNITTESTS */
}

/**
 * @}
 */
