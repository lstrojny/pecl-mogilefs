PHP_ARG_WITH(mogilefs, for mogilefs support,
[  --with-mogilefs			 Include mogilefs support])


if test "$PHP_MOGILEFS" != "no"; then
	paths="/usr /usr/local /sw"

	for path in $paths; do
		if test -x "$path/bin/xml2-config"; then
			XML2_CONFIG=$path/bin/xml2-config
			break
		fi
	done

	test -z "$XML2_CONFIG" && AC_MSG_ERROR(Cannot find libxml2)

	for path in $paths; do
		if test -x "$path/bin/neon-config"; then
			NEON_CONFIG=$path/bin/neon-config
			break
		fi
	done

	test -z "$NEON_CONFIG" && AC_MSG_ERROR(Cannot find libneon)

	MOGILEFS_LIBS=$($NEON_CONFIG --libs)
	MOGILEFS_INCS=$($NEON_CONFIG --cflags)

	PHP_EVAL_LIBLINE($MOGILEFS_LIBS, MOGILEFS_SHARED_LIBADD)
	PHP_EVAL_INCLINE($MOGILEFS_INCS)
	PHP_SUBST(MOGILEFS_SHARED_LIBADD)
	PHP_NEW_EXTENSION(mogilefs, mogilefs.c, $ext_shared)
fi
