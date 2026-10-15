/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
 *
 * xdg-desktop-portal-certificate
 */

/* URI imports resolve through p11-kit configuration; tools/module-smoke.sh supplies the portal and display. */

#include <stdlib.h>

#include <gio/gio.h>

static gboolean accept_any_server(GTlsConnection* connection, GTlsCertificate* peer,
                                  GTlsCertificateFlags errors, gpointer user_data)
{
	/* Skip fixture server validation; the server verifies the client credential under test. */
	return TRUE;
}

int main(int argc, char** argv)
{
	g_autoptr(GError) error = NULL;
	g_autoptr(GTlsCertificate) certificate = NULL;
	g_autoptr(GSocketClient) client = NULL;
	g_autoptr(GSocketConnection) connection = NULL;
	g_autoptr(GIOStream) tls = NULL;
	g_autoptr(GSocketConnectable) identity = NULL;
	char reply[64] = { 0 };
	gsize written = 0;
	gsize read = 0;

	if (argc != 5)
	{
		g_printerr("usage: gtls-client CERTIFICATE-URI KEY-URI HOST PORT\n");
		return 64;
	}

	certificate = g_tls_certificate_new_from_pkcs11_uris(argv[1], argv[2], &error);
	if (certificate == NULL)
	{
		g_printerr("FAIL: no GTlsCertificate from the PKCS#11 URIs: %s\n", error->message);
		return 1;
	}
	g_print("built a GTlsCertificate from %s\n", argv[1]);

	client = g_socket_client_new();
	connection = g_socket_client_connect_to_host(client, argv[3], (guint16) atoi(argv[4]), NULL,
	                                            &error);
	if (connection == NULL)
	{
		g_printerr("FAIL: could not connect: %s\n", error->message);
		return 1;
	}

	identity = g_network_address_new(argv[3], (guint16) atoi(argv[4]));
	tls = g_tls_client_connection_new(G_IO_STREAM(connection), identity, &error);
	if (tls == NULL)
	{
		g_printerr("FAIL: no TLS connection: %s\n", error->message);
		return 1;
	}

	g_tls_connection_set_certificate(G_TLS_CONNECTION(tls), certificate);
	g_signal_connect(tls, "accept-certificate", G_CALLBACK(accept_any_server), NULL);

	if (!g_tls_connection_handshake(G_TLS_CONNECTION(tls), NULL, &error))
	{
		g_printerr("FAIL: handshake: %s\n", error->message);
		return 1;
	}
	g_print("handshake completed\n");

	if (!g_output_stream_write_all(g_io_stream_get_output_stream(tls), "hello\n", 6, &written,
	                               NULL, &error))
	{
		g_printerr("FAIL: write: %s\n", error->message);
		return 1;
	}

	/* Use one read because fixture closure without close_notify is a TLS error. */
	if (g_input_stream_read_all(g_io_stream_get_input_stream(tls), reply, sizeof(reply) - 1,
	                            &read, NULL, &error))
	{
		(void) 0;
	}
	else if (read == 0)
	{
		g_printerr("FAIL: read: %s\n", error->message);
		return 1;
	}
	else
	{
		g_clear_error(&error);
	}

	g_io_stream_close(tls, NULL, NULL);

	g_print("server said: %s", reply);

	return g_str_has_prefix(reply, "PASS") ? 0 : 1;
}
