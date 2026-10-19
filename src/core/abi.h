/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef XCC_ABI_H
#define XCC_ABI_H
#include <stdint.h>
/* Views and request specs share one ABI version; append fields using struct_size. */
#define XCC_ABI_VERSION 1u
/* Keep extensions beyond the original struct's tail padding in C and C++. */
#ifdef __cplusplus
#define XCC_ALIGNAS(n) alignas(n)
#define XCC_ALIGNOF(type) alignof(type)
#else
#define XCC_ALIGNAS(n) _Alignas(n)
#define XCC_ALIGNOF(type) _Alignof(type)
#endif
/* Round the end of an original prefix to its original alignment, independently
 * of the alignment or offset of any subsequently appended member. */
#define XCC_PADDED_SIZE(end, alignment) (((end) + (alignment) - 1) / (alignment) * (alignment))
#define XCC_MAX_ALIGNOF(a, b) (XCC_ALIGNOF(a) > XCC_ALIGNOF(b) ? XCC_ALIGNOF(a) : XCC_ALIGNOF(b))
/* Only explicitly marked entry points cross the shared-library boundary. */
#if defined(__GNUC__)
#define XCC_API __attribute__((visibility("default")))
#else
#define XCC_API
#endif
#endif
