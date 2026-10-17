/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

/* tools/nss-smoke.sh supplies the private stack, chooser driver and short grant lifetime. */

#include <stdio.h>

#include <cert.h>
#include <cryptohi.h>
#include <keyhi.h>
#include <nss.h>
#include <pk11pub.h>
#include <prerror.h>
#include <prinrval.h>
#include <prthread.h>
#include <secitem.h>

static PRBool sign_and_verify(CERTCertificate* certificate, SECKEYPrivateKey* key)
{
	static const unsigned char message[] = "portal NSS refresh smoke";
	SECItem signature = { siBuffer, NULL, 0 };
	SECKEYPublicKey* public_key = CERT_ExtractPublicKey(certificate);
	SECStatus status = SECFailure;

	if (public_key != NULL &&
	    SEC_SignData(&signature, message, sizeof(message) - 1, key,
	                 SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION) == SECSuccess)
	{
		status = VFY_VerifyDataDirect(message, sizeof(message) - 1, public_key, &signature,
		                              SEC_OID_PKCS1_RSA_ENCRYPTION, SEC_OID_SHA256,
		                              NULL, NULL);
	}
	if (public_key != NULL)
		SECKEY_DestroyPublicKey(public_key);
	SECITEM_FreeItem(&signature, PR_FALSE);
	return status == SECSuccess;
}

int main(int argc, char** argv)
{
	CERTCertificate* first = NULL;
	CERTCertificate* second = NULL;
	SECKEYPrivateKey* first_key = NULL;
	SECKEYPrivateKey* second_key = NULL;
	PK11SlotInfo* slot = NULL;
	PRIntervalTime start;
	int series;
	int result = 1;

	if (argc != 3)
	{
		fprintf(stderr, "usage: %s sql:database token:nickname\n", argv[0]);
		return 2;
	}
	if (NSS_Init(argv[1]) != SECSuccess)
	{
		fprintf(stderr, "NSS_Init failed: %d\n", PR_GetError());
		return 1;
	}
	printf("NSS %s\n", NSS_GetVersion());
	first = PK11_FindCertFromNickname(argv[2], NULL);
	if (first == NULL)
		goto done;
	first_key = PK11_FindKeyByAnyCert(first, NULL);
	if (first_key == NULL || !sign_and_verify(first, first_key))
		goto done;
	slot = PK11_ReferenceSlot(first_key->pkcs11Slot);
	series = PK11_GetSlotSeries(slot);
	printf("first signature verified; series=%d\n", series);
	fflush(stdout);

	/* Exercise ordinary presence polling; never force NSS token initialization or reset its delay. */
	start = PR_IntervalNow();
	while (PR_IntervalNow() - start < PR_SecondsToInterval(45))
	{
		if (PK11_IsPresent(slot) && PK11_GetSlotSeries(slot) != series)
			break;
		PR_Sleep(PR_MillisecondsToInterval(100));
	}
	if (PK11_GetSlotSeries(slot) == series)
	{
		fprintf(stderr, "NSS did not advance the slot series after grant expiry\n");
		goto done;
	}
	printf("NSS refreshed the token; series=%d\n", PK11_GetSlotSeries(slot));

	/* Keep the first cert and key alive while NSS resolves the replacement handles. */
	second = PK11_FindCertFromNickname(argv[2], NULL);
	if (second == NULL)
		goto done;
	second_key = PK11_FindKeyByAnyCert(second, NULL);
	if (second_key == NULL || second_key->pkcs11Slot != slot ||
	    second_key->pkcs11ID == first_key->pkcs11ID ||
	    !sign_and_verify(second, second_key))
		goto done;
	puts("PASS: two verified signatures across expiry in one NSS process");
	result = 0;

done:
	if (result != 0)
		fprintf(stderr, "NSS refresh failed: %d\n", PR_GetError());
	if (slot != NULL)
		PK11_FreeSlot(slot);
	if (second_key != NULL)
		SECKEY_DestroyPrivateKey(second_key);
	if (first_key != NULL)
		SECKEY_DestroyPrivateKey(first_key);
	if (second != NULL)
		CERT_DestroyCertificate(second);
	if (first != NULL)
		CERT_DestroyCertificate(first);
	if (NSS_Shutdown() != SECSuccess)
	{
		fprintf(stderr, "NSS_Shutdown failed: %d\n", PR_GetError());
		result = 1;
	}
	return result;
}
