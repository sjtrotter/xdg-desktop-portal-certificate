/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CERTIFICATE_EXPORT_FACADE_H
#define CERTIFICATE_EXPORT_FACADE_H

#include <glib.h>

/** @file
 *  The synthetic PKCS#11 facade. EXPERIMENTAL, OPT-IN, MILESTONE 2.
 *
 *  ================================================================================
 *  READ THIS BEFORE ASSUMING p11-kit DOES THE WORK.
 *
 *  It does not. Stock `p11-kit server` takes TOKEN URIs; its unit of exposure is a
 *  token, not an object. It forwards the general PKCS#11 interface, including object
 *  creation and key generation. Login state does NOT cross the forwarding boundary: the
 *  consumer's TLS stack opens its own sessions and makes its own C_Login call. And
 *  p11-kit-client.so is located through process-level configuration plus a single
 *  P11_KIT_SERVER_ADDRESS, which does not accommodate concurrent per-request grants.
 *
 *  TOKEN-SCOPED FORWARDING IS INSUFFICIENT ISOLATION. On a PIV card it means the whole
 *  card: authentication, signing, key-management and card-authentication keys. If the
 *  consent dialog says "this certificate" and the endpoint exposes the token, the dialog
 *  is lying.
 *
 *  See docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md for all ten
 *  failure modes.
 *  ================================================================================
 *
 *  WHAT THIS IS INSTEAD: a CK_FUNCTION_LIST this project implements, served over a
 *  socket. p11-kit contributes the RPC TRANSPORT only --
 *  p11_kit_remote_serve_module(CK_FUNCTION_LIST *module, int in_fd, int out_fd), declared
 *  in p11-kit/remote.h behind P11_KIT_FUTURE_UNSTABLE_API. Transport is the small part.
 *
 *  THIS IS A SECURITY-SENSITIVE PKCS#11 IMPLEMENTATION FACING A HOSTILE PEER OVER A WIRE
 *  PROTOCOL. It is not plumbing. It is budgeted at 5-9 person-weeks on its own, it runs
 *  in ITS OWN PROCESS holding no PIN and reaching the card only through the broker, and
 *  it is the first thing that should be fuzzed.
 *
 *  WHAT IT MUST ENFORCE, at every entry point:
 *
 *   - one synthetic slot containing one synthetic token;
 *   - only the granted leaf certificate, its public key, its private key, and explicitly
 *     selected chain certificates -- no unrelated public or private objects;
 *   - SYNTHETIC HANDLES mapped to broker-owned underlying handles; a client-supplied
 *     handle is a lookup key, never an address;
 *   - read-only sessions only; CKF_RW_SESSION refused;
 *   - SO login refused entirely; user C_Login treated as an AUTHORIZATION-STATE
 *     TRANSITION that carries no PIN (lazy login: the broker prompts and logs into its
 *     OWN session at first C_Sign/C_Decrypt);
 *   - refuse C_InitToken, C_InitPIN, C_SetPIN, C_CreateObject, C_CopyObject,
 *     C_DestroyObject, C_SetAttributeValue, ALL key generation, ALL wrap/unwrap, ALL
 *     derivation unless a grant explicitly requires it, RNG seeding, and operation-state
 *     export/import;
 *   - restrict C_GetAttributeValue so sensitive and unexpected attributes cannot leak;
 *   - expose only allow-listed mechanisms and VALIDATE their parameters -- RSA-PSS hash,
 *     MGF and salt length above all -- rather than forwarding them;
 *   - refuse encrypt/decrypt unless the grant permits it; refuse signing until the grant
 *     is authorised;
 *   - NEVER trust client-supplied handles, lengths or operation state;
 *   - rate-limit, and terminate on expiry, revocation or card removal;
 *   - FILTER THE PKCS#11 v3 INTERFACE TABLES as well as the classic v2 function list.
 *     Filtering C_GetFunctionList alone leaves C_GetInterface as an unfiltered way back
 *     in.
 *
 *  HIDING OBJECTS DURING ENUMERATION IS NOT SCOPING. A caller with templates, cached
 *  handles, object creation, key generation, wrapping or derivation does not need
 *  C_FindObjects to reach the rest of the card. There is no allow-by-default path.
 *
 *  THE FD IS CREATED HERE AND RELAYED BY THE FRONTEND. The facade must reach the token
 *  session, and the token session belongs to this process, so the backend is the only
 *  side that can serve it. The frontend checks the grant, the owner and the policy, calls
 *  io.github.sjtrotter.impl.portal.Certificate1.OpenPkcs11Endpoint, and passes the
 *  descriptor straight through to the application without holding a copy. Upstream
 *  precedent for a descriptor crossing the impl boundary:
 *  org.freedesktop.impl.portal.RemoteDesktop.ConnectToEIS (out) and
 *  org.freedesktop.impl.portal.Secret.RetrieveSecret (in).
 *
 *  THE ENDPOINT IS A FILE DESCRIPTOR, NOT A PATH. A path is discoverable, races on the
 *  filesystem, and needs a bind mount to cross a sandbox; an fd passed over D-Bus is the
 *  capability and already crosses.
 *
 *  THE URIs ARE MEANINGFUL ONLY ON THIS ENDPOINT. A URI without an endpoint that
 *  resolves it is not a capability and is never returned alone. NO pin-value AND NO
 *  pin-source EVER APPEARS IN A URI THIS SERVICE EMITS.
 *
 *  WHY THIS MIGHT NOT WORK AT ALL, and what happens then: consumers may be unable to LOAD
 *  a per-request module. A PKCS#11 URI cannot name a socket,
 *  g_tls_certificate_new_from_pkcs11_uris() has no module parameter, and a browser's
 *  network process may have started before the endpoint existed. The most plausible
 *  resolution is the OPPOSITE SHAPE: one broker module PERMANENTLY REGISTERED in p11-kit
 *  configuration at install time, exposing SYNTHETIC GRANT-BOUND SLOTS, with
 *  OpenPkcs11Endpoint returning a URI that module resolves rather than a new module.
 *  docs/SPIKES.md S3 decides; endpoint_version exists so the answer can change the wire
 *  format. Note the security consequence in docs/SECURITY.md: a shared, always-loaded
 *  module must enforce grant binding by caller identity rather than by socket.
 *
 *  Sketch only; nothing here is implemented.
 */

#define CERTIFICATE_ENDPOINT_VERSION 1u

typedef struct CertificateFacade CertificateFacade;

/** Create a facade for @session_handle and return the endpoint socket fd for the
 *  frontend to relay. The facade runs in its own process. The URIs it fills in are valid
 *  only on this endpoint and carry no PIN attributes.
 *
 *  @app_id is passed because grant binding may have to be enforced by CALLER IDENTITY
 *  rather than by socket, if docs/SPIKES.md S3 forces the single-permanently-registered-
 *  module architecture. It is the frontend's answer, not anything this process worked
 *  out. */
CertificateFacade* certificate_facade_open(const char* session_handle, const char* app_id,
                                       int* endpoint_fd,
                                       char** certificate_uri, char** private_key_uri,
                                       GError** error);

/** Poison the endpoint: refuse every further call with a device error, cancel in-flight
 *  operations, and NEVER rebind to a card inserted later. Called on release, expiry,
 *  owner disconnect, and card removal. Reinsertion requires explicit reselection even
 *  when the label and slot number match, because they prove nothing about which card is
 *  in the reader. */
void certificate_facade_poison(CertificateFacade* facade, const char* reason);

/** Reap the helper process and close the socket. */
void certificate_facade_close(CertificateFacade* facade);

#endif /* CERTIFICATE_EXPORT_FACADE_H */
