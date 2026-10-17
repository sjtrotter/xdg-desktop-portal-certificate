/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 */
#ifndef XCC_SECRET_H
#define XCC_SECRET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct _XccSecret XccSecret;

XccSecret* xcc_secret_new(void);
/* Writable access invalidates the length; capacity includes space for the terminator. */
uint8_t* xcc_secret_data(XccSecret* secret, size_t* capacity);
/* Accept 1..511 bytes without embedded NUL; terminate on success, wipe on rejection. */
bool xcc_secret_set_length(XccSecret* secret, size_t length);
void xcc_secret_free(XccSecret* secret);

/* Borrowed until writable access or free; no PIN copy is made. */
const char* xcc_secret_view(const XccSecret* secret);
size_t xcc_secret_length(const XccSecret* secret);

#endif
