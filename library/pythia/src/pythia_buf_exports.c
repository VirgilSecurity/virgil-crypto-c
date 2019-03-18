/**
 * Copyright (C) 2015-2018 Virgil Security Inc.

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <relic/relic.h>
#include <relic/relic_err.h>
#include <pythia.h>
#include "pythia_buf.h"
#include "pythia_buf_exports.h"

static void
check_size_read(const pythia_buf_t *buf, size_t min_size, size_t max_size) {
    if (!buf || buf->len < min_size || buf->len > max_size)
        THROW(ERR_NO_BUFFER);
}

static void
check_size_write(const pythia_buf_t *buf, size_t min_size) {
    if (!buf || buf->allocated < min_size)
        THROW(ERR_NO_BUFFER);
}

void
bn_read_buf(bn_t b, const pythia_buf_t *buf) {
    check_size_read(buf, 2, PYTHIA_BN_BUF_SIZE);

    uint8_t sign = buf->p[0];

    if (sign != BN_POS && sign != BN_NEG)
        THROW(ERR_NO_VALID);

    bn_read_bin(b, buf->p + 1, (int)(buf->len - 1));
    b->sign = sign;
}

void
gt_read_buf(gt_t g, const pythia_buf_t *buf) {
    check_size_read(buf, 1, PYTHIA_GT_BUF_SIZE);

    // TODO replace with proper sanity check
    int zeroBytes = 0;
    for (size_t i = 0; i < buf->len; i++) {
        zeroBytes += buf->p[i] == 0;
    }
    if (zeroBytes > 24)
        THROW(ERR_NO_VALID);

    gt_read_bin(g, buf->p, (int)buf->len);
}

void
g1_read_buf(g1_t g, const pythia_buf_t *buf) {
    check_size_read(buf, 1, PYTHIA_G1_BUF_SIZE);
    g1_read_bin(g, buf->p, (int)buf->len);
    if (!g1_is_valid(g))
        THROW(ERR_NO_VALID);
}

void
g2_read_buf(g2_t g, const pythia_buf_t *buf) {
    check_size_read(buf, 1, PYTHIA_G2_BUF_SIZE);
    g2_read_bin(g, buf->p, (int)buf->len);
    if (!g2_is_valid(g))
        THROW(ERR_NO_VALID);
}

void
bn_write_buf(pythia_buf_t *buf, bn_t b) {
    int size = bn_size_bin(b) + 1;
    check_size_write(buf, (size_t)size);
    bn_write_bin(buf->p + 1, size - 1, b);
    buf->p[0] = (uint8_t)b->sign;
    buf->len = (size_t)size;
}

void
g2_write_buf(pythia_buf_t *buf, g2_t e) {
    int size = g2_size_bin(e, 1);
    check_size_write(buf, (size_t)size);
    g2_write_bin(buf->p, size, e, 1);
    buf->len = (size_t)size;
}

void
gt_write_buf(pythia_buf_t *buf, gt_t g) {
    int size = gt_size_bin(g, 1);
    check_size_write(buf, (size_t)size);
    gt_write_bin(buf->p, size, g, 1);
    buf->len = (size_t)size;
}

void
g1_write_buf(pythia_buf_t *buf, g1_t g) {
    int size = g1_size_bin(g, 1);
    check_size_write(buf, (size_t)size);
    g1_write_bin(buf->p, size, g, 1);
    buf->len = (size_t)size;
}
