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

#ifndef PYTHIA_PYTHIA_BUF_SIZES_C_H
#define PYTHIA_PYTHIA_BUF_SIZES_C_H

#include <relic/relic.h>

#define DEF_PYTHIA_G1_BUF_SIZE FP_BYTES + 1

#define DEF_PYTHIA_G2_BUF_SIZE 2 * FP_BYTES + 1

#define DEF_PYTHIA_GT_BUF_SIZE 8 * FP_BYTES

#define DEF_PYTHIA_BN_BUF_SIZE DEF_PYTHIA_G1_BUF_SIZE + 1

#define DEF_PYTHIA_BIN_MIN_BUF_SIZE 1

#define DEF_PYTHIA_BIN_MAX_BUF_SIZE 128

#endif // PYTHIA_PYTHIA_BUF_SIZES_C_H
