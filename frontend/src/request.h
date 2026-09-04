/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CERTIFICATE_FRONTEND_REQUEST_H
#define CERTIFICATE_FRONTEND_REQUEST_H

#include <glib.h>

/** @file
 *  io.github.sjtrotter.portal.Request -- one interactive transaction, frontend side.
 *
 *  Copied closely from org.freedesktop.portal.Request and from xdg-desktop-portal's
 *  desktop-portal/xdp-request.c, because that pattern is correct and callers already
 *  know it. Copying the pattern is not claiming the namespace; see
 *  docs/decisions/0003-own-namespace-before-freedesktop.md.
 *
 *  The object path is
 *  /io/github/sjtrotter/portal/Certificate/request/<sender>/<handle_token>, where <sender>
 *  is the caller's unique name with the leading ':' removed and '.' replaced by '_'.
 *  The caller can therefore compute the path and SUBSCRIBE BEFORE CALLING, which is the
 *  entire reason for the pattern: there is no window in which a response can be missed.
 *
 *  Close() cancels. There is no separate Cancel method, and after Close() no success
 *  response follows.
 *
 *  TWO REQUEST OBJECTS, ONE TRANSACTION. This is the part that is new with the
 *  frontend/backend split and the part that gets it wrong quietly:
 *
 *    application  --Close()-->  FRONTEND Request  --Close()-->  BACKEND Request
 *      (io.github.sjtrotter.portal.Request)   (io.github.sjtrotter.impl.portal.Request)
 *
 *  The frontend exports the object the application talks to, and separately exports an
 *  impl Request proxy on the backend's connection at the @handle path it passed to the
 *  backend. It forwards Close() and it translates the backend's (response, results)
 *  return into the Response signal. THE APPLICATION NEVER TOUCHES THE BACKEND'S REQUEST
 *  OBJECT, and the backend never sees the application's.
 *
 *  The frontend also POLICES THE RESPONSE. A backend that returns results the frontend
 *  did not ask for, or a mechanism outside the allow-list, or a lifetime longer than the
 *  ceiling, does not get to widen a grant by saying so: the frontend intersects, and a
 *  backend that tries is a bug worth logging by reason code.
 *
 *  Sketch only; nothing here is implemented.
 */

/** Response codes. Exactly ONE terminal response is ever emitted per request. */
typedef enum
{
	CERTIFICATE_RESPONSE_SUCCESS = 0,   /**< results as documented per method */
	CERTIFICATE_RESPONSE_CANCELLED = 1, /**< by the user, or by Close() */
	CERTIFICATE_RESPONSE_OTHER = 2      /**< results carry "error" and "error_message" */
} CertificateResponse;

typedef struct CertificateRequest CertificateRequest;

/** Everything one transaction owns, so that one destructor closes all of it.
 *
 *  Held: the caller's unique bus name, the RESOLVED APP INFO (app-info.h) and its
 *  honesty level, the validated options, the session this request acts on, the proxy
 *  for the backend's Request object, and the cancellable that reaches the backend call.
 *
 *  Destroyed on exactly one of: response delivered, Close(), caller disconnect, timeout,
 *  frontend shutdown, backend vanishing. Every one of those closes the backend's Request
 *  too -- a cancelled transaction must never leave a PIN dialog on a user's screen for
 *  the next transaction to inherit, and after the split that dialog belongs to a
 *  different process.
 *
 *  Timeouts: five minutes by default for an interactive request, with a hard ceiling
 *  around fifteen. Smart-card flows make short fixed timeouts hostile -- a user hunting
 *  for a reader is a normal user. The timeout is the FRONTEND'S, because it is policy;
 *  the backend gets a cancellation, not a deadline. */
CertificateRequest* certificate_request_new(GDBusMethodInvocation* invocation,
                                        const char* handle_token, GVariant* options,
                                        GError** error);

/** Emit the one terminal Response and destroy the transaction. Calling this twice is a
 *  programming error; the second call is dropped and logged as a reason code. A
 *  completion already atomically committed wins over a simultaneous cancellation, and
 *  every other late event is discarded. */
void certificate_request_respond(CertificateRequest* request, CertificateResponse response,
                               GVariant* results);

/** Cancel: from Close(), from caller disconnect, from timeout, from shutdown, from the
 *  backend disappearing. Calls Close() on the backend's Request object first, so the
 *  window goes away before the application is told anything. */
void certificate_request_cancel(CertificateRequest* request, const char* reason_code);

/** Attach the backend-side Request proxy created for this transaction, so that Close()
 *  reaches it. The frontend chooses the @handle path and passes it to the backend, which
 *  exports the object -- the same direction as upstream's
 *  xdp_request_set_impl_request(). */
void certificate_request_set_impl(CertificateRequest* request, GDBusProxy* impl_request);

#endif /* CERTIFICATE_FRONTEND_REQUEST_H */
