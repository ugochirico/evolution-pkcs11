#include <stdio.h>
#include <libebook/libebook.h>
#include <shell/e-shell.h>

int main (int argc, char **argv)
{
	GError *error;
	ESource *source = NULL;

	e_shell_get_default();
	printf("Hello addressbook-access-test\n");

	return 0;
}
