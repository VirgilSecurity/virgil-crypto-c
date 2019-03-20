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

#ifndef PYTHIA_PYTHIA_INIT_H
#define PYTHIA_PYTHIA_INIT_H

#ifdef __cplusplus
extern "C" {
#endif

/// Struct used to initialize pythia
typedef struct pythia_init_args {
    void (*callback)(uint8_t *, int, void *); /// Callback called to obtain random value
    void *args;                               /// Arguments passed to callback
} pythia_init_args_t;

/// Initializer pythia. This function is not thread-safe and should be called before any other pythia call
/// \param init_args initialization arguments
/// \return 0 if succeeded, -1 otherwise
int
pythia_init(const pythia_init_args_t *init_args);

/// Clears pythia data. Should be called after all pythia interactions are ended
void
pythia_deinit(void);

#ifdef __cplusplus
}
#endif

#endif // PYTHIA_PYTHIA_INIT_H
