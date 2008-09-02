AUTOMAKE_OPTIONS=foreign no-dependencies

bin_PROGRAMS = ykpasswd ykvalidate

ykpasswd_SOURCES = ykpasswd.c ykpasswd.h
ykpasswd_LDADD = ../lib/libyubipam.la

ykvalidate_SOURCES = ykvalidate.c ykvalidate.h
ykvalidate_LDADD = ../lib/libyubipam.la

INCLUDES = -I../ -I../lib

