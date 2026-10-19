/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef XCC_ABI_H
#define XCC_ABI_H
#include <stdint.h>
/* Views and request specs share one ABI version; append fields using struct_size. */
#define XCC_ABI_VERSION 1u
/* Only explicitly marked entry points cross the shared-library boundary. */
#if defined(__GNUC__)
#define XCC_API __attribute__((visibility("default")))
#else
#define XCC_API
#endif
#endif
