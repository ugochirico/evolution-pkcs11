AM_CFLAGS=-Wall -I/usr/include/nspr4 -I/home/yuuma/local/unstable/include/evolution-data-server -I/usr/lib64/glib-2.0/include -I/usr/include/glib-2.0 -I/usr/include/libsoup-2.4  -I/usr/include/libxml2 -I/usr/include/evolution-3.10 -I/usr/include/gtk-3.0 -I/usr/include/pango-1.0 -I/usr/include/cairo -I/usr/include/gdk-pixbuf-2.0 -I/usr/include/atk-1.0 -I/usr/include/libgtkhtml-4.0/editor -I/usr/include/libgtkhtml-4.0 -I/usr/include/webkitgtk-3.0 -I/home/yuuma/local/unstable/include/evolution-3.14


lib_LTLIBRARIES = evolution-pkcs11.la
evolution_pkcs11_la_SOURCES = pkcs11.c pkcs11.h pkcs11f.h pkcs11t.h object.h object.c session.h util.h util.c 
evolution_pkcs11_la_LDFLAGS= -module 
evolution_pkcs11_la_LIBADD = -ledataserver-1.2 -lebook-contacts-1.2  -lebook-1.2 -L/usr/lib64/evolution/3.10 -levolution-util



