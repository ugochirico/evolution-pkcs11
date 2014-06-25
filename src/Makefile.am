AM_CFLAGS=-Wall -I/usr/include/nspr4 -I/usr/include/evolution-data-server -I/usr/lib64/glib-2.0/include -I/usr/include/glib-2.0 -I/usr/include/libsoup-2.4  -I/usr/include/libxml2 -I/usr/include/evolution-3.10 -I/usr/include/gtk-3.0 -I/usr/include/pango-1.0 -I/usr/include/cairo -I/usr/include/gdk-pixbuf-2.0 -I/usr/include/atk-1.0 -I/usr/include/libgtkhtml-4.0/editor -I/usr/include/libgtkhtml-4.0 -I/usr/include/webkitgtk-3.0 

lib_LTLIBRARIES = evolution-pkcs11.la
evolution_pkcs11_la_SOURCES = pkcs11.c pkcs11.h pkcs11f.h pkcs11t.h object.h object.c
evolution_pkcs11_la_LDFLAGS= -module -L/usr/lib64/evolution/3.10 
evolution_pkcs11_la_LIBADD=-levolution-shell -lnss3 -lplc4 -levolution-util -lebook-1.2 -lglib-2.0 -lebook-contacts-1.2 -ledataserver-1.2


