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

#ifndef PYTHIA_PYTHIA_BUF_EXPORTS_H
#define PYTHIA_PYTHIA_BUF_EXPORTS_H

#include "pythia_buf.h"

#include <relic/relic.h>

#ifdef __cplusplus
extern "C" {
#endif

void bn_read_buf(bn_t b, const pythia_buf_t *buf);
void gt_read_buf(gt_t g, const pythia_buf_t *buf);
void g1_read_buf(g1_t g, const pythia_buf_t *buf);
void g2_read_buf(g2_t g, const pythia_buf_t *buf);
void bn_write_buf(pythia_buf_t *buf, bn_t b);
void g2_write_buf(pythia_buf_t *buf, g2_t e);
void gt_write_buf(pythia_buf_t *buf, gt_t g);
void g1_write_buf(pythia_buf_t *buf, g1_t g);

#ifdef __cplusplus
}
#endif

#endif //PYTHIA_PYTHIA_BUF_EXPORTS_H
