AM_CFLAGS=-Wall $(EBOOK_CFLAGS)
AM_LDFLAGS=-ldl 

bin_PROGRAMS = test_app addressbook_access_test loadtest
test_app_SOURCES = test-app.c test-session.c test-search.c test-attribute-value.c
test_app_LDADD = $(GLIB_LIBS)

addressbook_access_test_SOURCES = addressbook-access-test.c 
addressbook_access_test_LDADD = $(EBOOK_LIBS)
loadtest_SOURCES = test.c
loadtest_LDADD = $(NSS_LIBS)
