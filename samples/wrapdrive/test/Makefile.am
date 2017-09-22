AM_CFLAGS=-Wall -O0 -fno-strict-aliasing

bin_PROGRAMS=test_dummy test_cipher_iommu test_cipher_sync

test_dummy_SOURCES=test_dummy.c ../wd.h ../wd_dummy.h

test_dummy_LDADD=../.libs/libwd.a
test_dummy_LDFLAGS=-lsysfs

test_cipher_iommu_SOURCES=test_cipher_common.h test_cipher_iommu.c

test_cipher_iommu_LDADD=../.libs/libwd.a
test_cipher_iommu_LDFLAGS=-lsysfs

test_cipher_sync_SOURCES=test_cipher_common.h test_cipher_sync.c

test_cipher_sync_LDADD=../.libs/libwd.a
test_cipher_sync_LDFLAGS=-lsysfs
