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

#include "pythia_buf.h"

pythia_buf_t *pythia_buf_new(void) {
    pythia_buf_t *buf = (pythia_buf_t *)malloc(sizeof(pythia_buf_t));
    buf->p = NULL;
    buf->allocated = 0;
    buf->len = 0;

    return buf;
}

/// Frees pythia buffer (WARNING: Doesn't free actual buffer memory, only memory needed for pythia_buf instance itself)
void pythia_buf_free(pythia_buf_t *buf) {
    free(buf);
}

void pythia_buf_setup(pythia_buf_t *buf, uint8_t *p, size_t allocated, size_t len) {
    buf->p = p;
    buf->allocated = allocated;
    buf->len = len;
}
