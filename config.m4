PHP_ARG_WITH(mogilefs, for mogilefs support,
[  --with-mogilefs             Include mogilefs support])


if test "$PHP_MOGILEFS" != "no"; then
	for i in $PHP_MOGILEFS /usr/local /usr; do
		if test -x "$i/bin/neon-config"; then
			NEON_CONFIG=$i/bin/neon-config
			break
		fi
	done

	MOGILEFS_LIBS=$($NEON_CONFIG --libs)
	MOGILEFS_INCS=$($NEON_CONFIG --cflags)

	PHP_EVAL_LIBLINE($MOGILEFS_LIBS, MOGILEFS_SHARED_LIBADD)
	PHP_EVAL_INCLINE($MOGILEFS_INCS)
	PHP_SUBST(MOGILEFS_SHARED_LIBADD)
	PHP_NEW_EXTENSION(mogilefs, mogilefs.c, $ext_shared)
fi
