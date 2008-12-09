dnl $Id$
dnl config.m4 for extension mogilefs

dnl Comments in this file start with the string 'dnl'.

dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

PHP_ARG_WITH(mogilefs, for mogilefs support,
[  --with-mogilefs             Include mogilefs support])

dnl Otherwise use enable:

dnl PHP_ARG_ENABLE(mogilefs, whether to enable mogilefs support,
dnl Make sure that the comment is aligned:
dnl [  --enable-mogilefs           Enable mogilefs support])


if test "$PHP_MOGILEFS" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-mogilefs -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/mogilefs.h"  # you most likely want to change this
  dnl if test -r $PHP_MOGILEFS/$SEARCH_FOR; then # path given as parameter
  dnl   MOGILEFS_DIR=$PHP_MOGILEFS
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for mogilefs files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       MOGILEFS_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$MOGILEFS_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the mogilefs distribution])
  dnl fi

  dnl # --with-mogilefs -> add include path
  dnl PHP_ADD_INCLUDE($MOGILEFS_DIR/include)

  dnl # --with-mogilefs -> check for lib and symbol presence
  dnl LIBNAME=mogilefs # you may want to change this
  dnl LIBSYMBOL=mogilefs # you most likely want to change this 

  dnl PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $MOGILEFS_DIR/lib, MOGILEFS_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_MOGILEFSLIB,1,[ ])
  dnl ],[
  dnl   AC_MSG_ERROR([wrong mogilefs lib version or lib not found])
  dnl ],[
  dnl   -L$MOGILEFS_DIR/lib -lm -ldl
  dnl ])
  dnl
  dnl PHP_SUBST(MOGILEFS_SHARED_LIBADD)

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
