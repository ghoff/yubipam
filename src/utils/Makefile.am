AUTOMAKE_OPTIONS=foreign no-dependencies

bin_PROGRAMS = ykvalidate
sbin_PROGRAMS = ykpasswd yk_chkpwd

sbindir = /sbin

ykpasswd_SOURCES = ykpasswd.c ykpasswd.h
ykpasswd_LDADD = ../lib/libyubipam.la

ykvalidate_SOURCES = ykvalidate.c ykvalidate.h
ykvalidate_LDADD = ../lib/libyubipam.la

yk_chkpwd_SOURCES = yk_chkpwd.c
yk_chkpwd_LDADD = ../lib/libyubipam.la

INCLUDES = -I../ -I../lib

