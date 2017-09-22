ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = foreign subdir-objects
AM_CFLAGS=-Wall -O0 -fno-strict-aliasing

lib_LTLIBRARIES=libwd.la
libwd_la_SOURCES=wd.c wd_util.c wd_adapter.c wd.h wd_adapter.h\
		 wd_cipher.c wd_cipher.h \
		 wd_dummy.c wd_dummy.h \
		 drv/hisi_sec_udrv_v1.c drv/hisi_sec_udrv_v1.h \
		 drv/dummy_drv.c drv/dummy_drv.h

bin_PROGRAMS=wd_clean
wd_clean_SOURCES=wd_clean.c
wd_clean_LDADD=.libs/libwd.a


SUBDIRS=. test
