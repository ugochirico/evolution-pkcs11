AM_CFLAGS=-Wall -I/usr/include/evolution-data-server -I/usr/lib64/glib-2.0/include -I/usr/include/glib-2.0 -I/usr/include/libsoup-2.4 -I/usr/include/nspr4 -I/usr/include/libxml2 -I/usr/include/evolution-3.10 -I/usr/include/gtk-3.0 -I/usr/include/pango-1.0 -I/usr/include/cairo -I/usr/include/gdk-pixbuf-2.0 -I/usr/include/atk-1.0 -I/usr/include/libgtkhtml-4.0/editor -I/usr/include/libgtkhtml-4.0 -I/usr/include/webkitgtk-3.0 -O0 -I/home/yuuma/local/unstable/include/evolution-3.14 
AM_LDFLAGS=-ldl 

bin_PROGRAMS = test_app addressbook_access_test loadtest
test_app_SOURCES = test-app.c
addressbook_access_test_SOURCES = addressbook-access-test.c 
addressbook_access_test_LDADD = -ledataserver-1.2 -lebook-contacts-1.2  -lebook-1.2 -L/usr/lib64/evolution/3.10 -levolution-util
loadtest_SOURCES = test.c
loadtest_LDADD = -lnspr4 -lplc4 -lnss3
