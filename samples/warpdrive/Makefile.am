ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = foreign subdir-objects
AM_CFLAGS=-Wall -O0 -fno-strict-aliasing

lib_LTLIBRARIES=libwd.la
libwd_la_SOURCES=wd.c wd_util.c wd_adapter.c wd.h wd_adapter.h\
		 drv/hisi_zip_udrv.c drv/hisi_zip_udrv.h




SUBDIRS=. test
