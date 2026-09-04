/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef SMARTCARD_DBUS_REQUEST_H
#define SMARTCARD_DBUS_REQUEST_H

#include <glib.h>

/** @file
 *  io.github.sjtrotter.Smartcard1.Request -- one interactive transaction.
 *
 *  Copied closely from org.freedesktop.portal.Request, because that pattern is correct
 *  and callers already know it. Copying the pattern is not claiming the namespace; see
 *  docs/decisions/0003-own-namespace-before-freedesktop.md.
 *
 *  The object path is /io/github/sjtrotter/Smartcard1/request/<sender>/<handle_token>,
 *  where <sender> is the caller's unique name with the leading ':' removed and '.'
 *  replaced by '_'. The caller can therefore compute the path and SUBSCRIBE BEFORE
 *  CALLING, which is the entire reason for the pattern: there is no window in which a
 *  response can be missed.
 *
 *  Close() cancels. There is no separate Cancel method, and after Close() no success
 *  response follows.
 *
 *  Sketch only; nothing here is implemented.
 */

/** Response codes. Exactly ONE terminal response is ever emitted per request. */
typedef enum
{
	SMARTCARD_RESPONSE_SUCCESS = 0,   /**< results as documented per method */
	SMARTCARD_RESPONSE_CANCELLED = 1, /**< by the user, or by Close() */
	SMARTCARD_RESPONSE_OTHER = 2      /**< results carry "error" and "error_message" */
} SmartcardResponse;

typedef struct SmartcardRequest SmartcardRequest;

/** Everything one transaction owns, so that one destructor closes all of it.
 *
 *  Held: the caller's unique bus name, the resolved caller identity and its honesty
 *  level (src/log/redact.h has the rules for what may be logged about it), the options,
 *  the discovery cancellable, the chooser and PIN windows, and -- if the transaction
 *  succeeds -- the grant it created.
 *
 *  Destroyed on exactly one of: response delivered, Close(), caller disconnect, timeout,
 *  service shutdown. Every window it owns closes with it, including a PIN prompt: a
 *  cancelled transaction must never leave a PIN dialog on screen for the next
 *  transaction to inherit.
 *
 *  Timeouts: five minutes by default for an interactive request, with a hard ceiling
 *  around fifteen. Smart-card flows make short fixed timeouts hostile -- a user hunting
 *  for a reader is a normal user. */
SmartcardRequest* smartcard_request_new(const char* sender, const char* handle_token,
                                        GVariant* options, GError** error);

/** Emit the one terminal Response and destroy the transaction. Calling this twice is a
 *  programming error; the second call is dropped and logged as a reason code. A
 *  completion already atomically committed wins over a simultaneous cancellation, and
 *  every other late event is discarded. */
void smartcard_request_respond(SmartcardRequest* request, SmartcardResponse response,
                               GVariant* results);

/** Cancel: from Close(), from caller disconnect, from timeout, from shutdown. Closes
 *  every window, cancels discovery, and releases any grant this transaction created but
 *  had not yet returned. */
void smartcard_request_cancel(SmartcardRequest* request, const char* reason_code);

#endif /* SMARTCARD_DBUS_REQUEST_H */
