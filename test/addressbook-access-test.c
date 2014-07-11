#include <stdio.h>
#include <libebook/libebook.h>
#include <shell/e-shell.h>

int main (int argc, char **argv)
{
	GError *error = NULL;
	ESourceRegistry *registry;
	EClientCache *client_cache;
	EBookClient *client_addressbook;
	GList *addressbooks, *aux_addressbooks;
	GSList *contacts, *it;
	EBookQuery *final_query, *query_mail, *query_cert;
	gchar *query_string, *email;
	gboolean status;
	gchar *fullname;
	EContactCert *cert;
	gsize i;

	if (argc != 2) return 1;

	email = argv[1];
	 
	registry = e_source_registry_new_sync (NULL, &error);

	client_cache = e_client_cache_new (registry);
	addressbooks = e_source_registry_list_enabled (registry, E_SOURCE_EXTENSION_ADDRESS_BOOK);

	query_mail = e_book_query_field_test (E_CONTACT_EMAIL, E_BOOK_QUERY_CONTAINS, email);
	query_cert = e_book_query_field_exists (E_CONTACT_X509_CERT);
	final_query = e_book_query_andv (query_cert, query_mail, NULL);

	query_string = e_book_query_to_string (final_query);
	
	printf("Query String: %s\n", query_string);

	aux_addressbooks = addressbooks;
	while (aux_addressbooks != NULL) {

		client_addressbook = (EBookClient *) e_client_cache_get_client_sync (client_cache, (ESource *) aux_addressbooks->data, E_SOURCE_EXTENSION_ADDRESS_BOOK, NULL, &error);

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
