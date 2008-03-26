/*
 * Copyright (c) 2008 Timu EREN <selamtux@gmail.com>
 * Copyright (c) 2007 AHSEIN Khalid <mogilefs@capoune.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef PHP_MOGILEFS_H
#define PHP_MOGILEFS_H

extern zend_module_entry mogilefs_module_entry;
#define phpext_mogilefs_ptr &mogilefs_module_entry

#ifdef PHP_WIN32
#define PHP_MOGILEFS_API __declspec(dllexport)
#else
#define PHP_MOGILEFS_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

PHP_MINIT_FUNCTION(mogilefs);
PHP_MSHUTDOWN_FUNCTION(mogilefs);
PHP_RINIT_FUNCTION(mogilefs);
PHP_RSHUTDOWN_FUNCTION(mogilefs);
PHP_MINFO_FUNCTION(mogilefs);

PHP_FUNCTION(mogilefs_connect);
PHP_FUNCTION(mogilefs_close);
PHP_FUNCTION(mogilefs_get);
PHP_FUNCTION(mogilefs_get_domains);
PHP_FUNCTION(mogilefs_list_keys);
PHP_FUNCTION(mogilefs_list_fids);
PHP_FUNCTION(mogilefs_get_hosts);
PHP_FUNCTION(mogilefs_get_devices);
PHP_FUNCTION(mogilefs_sleep);
PHP_FUNCTION(mogilefs_stats);
PHP_FUNCTION(mogilefs_replicate);
PHP_FUNCTION(mogilefs_create_device);
PHP_FUNCTION(mogilefs_create_domain);
PHP_FUNCTION(mogilefs_delete_domain);
PHP_FUNCTION(mogilefs_create_class);
PHP_FUNCTION(mogilefs_update_class);
PHP_FUNCTION(mogilefs_delete_class);
PHP_FUNCTION(mogilefs_create_host);
PHP_FUNCTION(mogilefs_update_host);
PHP_FUNCTION(mogilefs_delete_host);
PHP_FUNCTION(mogilefs_set_weight);
PHP_FUNCTION(mogilefs_set_state);
PHP_FUNCTION(mogilefs_checker);
PHP_FUNCTION(mogilefs_monitor_round);
PHP_FUNCTION(mogilefs_put);
PHP_FUNCTION(mogilefs_delete);
PHP_FUNCTION(mogilefs_rename);

ZEND_BEGIN_MODULE_GLOBALS(mogilefs)
	int default_link;
ZEND_END_MODULE_GLOBALS(mogilefs)

/* In every utility function you add that needs to use variables
   in php_mogilefs_globals, call TSRMLS_FETCH(); after declaring other
   variables used by that function, or better yet, pass in TSRMLS_CC
   after the last function argument and declare your utility function
   with TSRMLS_DC after the last declared argument.  Always refer to
   the globals in your function as MOGILEFS_G(variable).  You are
   encouraged to rename these macros something shorter, see
   examples in any other php module directory.
*/

#ifdef ZTS
#define MOGILEFS_G(v) TSRMG(mogilefs_globals_id, zend_mogilefs_globals *, v)
#else
#define MOGILEFS_G(v) (mogilefs_globals.v)
#endif

#endif	/* PHP_MOGILEFS_H */

#define MOGILEFS_SOCK_BUF_SIZE 4096
#define MOGILEFS_DAV_SESSION_TIMEOUT 8
#define MOGILEFS_SOCK_STATUS_FAILED 0
#define MOGILEFS_SOCK_STATUS_DISCONNECTED 1
#define MOGILEFS_SOCK_STATUS_UNKNOWN 2
#define MOGILEFS_SOCK_STATUS_CONNECTED 3


typedef struct MogilefsSock_ {
	php_stream *stream;
	char					*host;
	char					*domain;
	unsigned short			port;
	long					timeout;
	long					failed;
	int						status;
} MogilefsSock;


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
