/*
 * evolution-pkcs11
 *
 * Copyright (C) 2014  Yuuma Sato
 *
 * evolution-pkcs11 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * evolution-pkcs11 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with evolution-pkcs11.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <libebook/libebook.h>

/* Test access to Evolution addressbook contacts */
int main (int argc, char **argv)
{
	GError *error = NULL;
	ESourceRegistry *registry;
	EBookClient *client_addressbook;
	GList *addressbooks, *aux_addressbooks;
	GSList *contacts, *it;
	EBookQuery *final_query, *query_mail, *query_cert;
	gchar *query_string, *email;
	gboolean status;
	gchar *fullname;
	EContactCert *cert;
	gsize i;

	if (argc != 2) {
		email = NULL;
	} else {
		email = argv[1];
	}
	 
	registry = e_source_registry_new_sync (NULL, &error);

	addressbooks = e_source_registry_list_enabled (registry, E_SOURCE_EXTENSION_ADDRESS_BOOK);

	if (email == NULL) {
		query_mail = NULL;
	}else {
		query_mail = e_book_query_field_test (E_CONTACT_EMAIL, E_BOOK_QUERY_IS, email);
	}
	query_cert = e_book_query_field_exists (E_CONTACT_X509_CERT);
	final_query = e_book_query_andv (query_cert, query_mail, NULL);

	query_string = e_book_query_to_string (final_query);
	
	printf("Query String: %s\n", query_string);

	aux_addressbooks = addressbooks;
	while (aux_addressbooks != NULL) {

		client_addressbook = (EBookClient *) e_book_client_connect_sync ((ESource *) aux_addressbooks->data, (guint32)-1, NULL, &error);

		status = e_book_client_get_contacts_sync (client_addressbook, query_string, &contacts, NULL, NULL);
		if (status && contacts != NULL) {
			for (it = contacts; it != NULL; it = it->next){
				fullname  = e_contact_get (it->data, E_CONTACT_FULL_NAME);
				printf ("Fullname: %s\n", fullname);
				cert = e_contact_get (it->data, E_CONTACT_X509_CERT);
				if (cert != NULL) {
					printf ("Size: %lu\n", cert->length);
					printf ("Cert: \n");
					for (i = 0; i < cert->length; i++) {
						printf ("%02X:", ((unsigned char *)cert->data)[i]);
					}
				}
			}
		} 

		aux_addressbooks = aux_addressbooks->next;
	}

	return 0;
}
