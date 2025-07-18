/* Copyright (C) 2015-2018 Open Information Security Foundation
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
 * \file
 *
 * \author Fupeng Zhao <fupeng.zhao@foxmail.com>
 *
 */

#ifndef SURICATA_DECODE_ETAG_H
#define SURICATA_DECODE_ETAG_H

#define ETAG_HEADER_LEN 6

typedef struct EtagHdr_ {
    uint8_t tci[6];
} __attribute__((__packed__)) EtagHdr;

#define GET_ETAG_PROTO(etag_hdr) ((((etag_hdr)->tci[4] & 0xFF) << 8) | ((etag_hdr)->tci[5] & 0xFF))

void DecodeETAGRegisterTests(void);

#endif /* SURICATA_DECODE_ETAG_H */
