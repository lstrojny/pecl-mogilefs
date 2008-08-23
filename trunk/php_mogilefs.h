/**
 * Copyright (c) 2008 Lars Strojny <lstrojny@php.net>
 * Copyright (c) 2008 Timu Eren <selamtux@gmail.com>
 * Copyright (c) 2007 Khalid Ahsein <mogilefs@capoune.net>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  * Neither the name of the PHP MogileFS authors nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PHP_MOGILEFS_H
#define PHP_MOGILEFS_H
#define PHP_MOGILEFS_VERSION "0.7.5b3"

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
PHP_FUNCTION(mogilefs_is_connected);

ZEND_BEGIN_MODULE_GLOBALS(mogilefs)
	int default_link;
ZEND_END_MODULE_GLOBALS(mogilefs)

#define mogilefs_sock_name "MogileFS Socket Buffer"

#define MOGILEFS_SOCK_WRITE_FREE(socket, cmd, cmd_len) \
	mogilefs_sock_write (socket, cmd, cmd_len, 1 TSRMLS_CC)
#define MOGILEFS_SOCK_WRITE(socket, cmd, cmd_len) \
	mogilefs_sock_write (socket, cmd, cmd_len, 0 TSRMLS_CC);

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

/* {{{ struct MogilefsSock */
typedef struct MogilefsSock_ {
	php_stream *stream;
	char					*host;
	char					*domain;
	unsigned short			port;
	long					timeout;
	long					failed;
	int						status;
} MogilefsSock;
/* }}} */

/* {{{ internal function protos */
PHPAPI int mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAMETERS, const char * const result, int result_len);
PHPAPI MogilefsSock* mogilefs_sock_server_init(char *m_host, int m_host_len, unsigned short m_port, char *m_domain, int m_domain_len, long timeout);
PHPAPI int mogilefs_sock_connect(MogilefsSock *mogilefs_sock TSRMLS_DC);
PHPAPI int mogilefs_sock_disconnect(MogilefsSock *mogilefs_sock TSRMLS_DC);
PHPAPI int mogilefs_sock_server_open(MogilefsSock *mogilefs_sock, int TSRMLS_DC);
PHPAPI int mogilefs_sock_get(zval *id, MogilefsSock **mogilefs_sock TSRMLS_DC);
PHPAPI int mogilefs_sock_write(MogilefsSock *mogilefs_sock, char *cmd, int cmd_len, int free_cmd TSRMLS_DC);
PHPAPI char * mogilefs_sock_read(MogilefsSock *mogilefs_sock, int *buf_len TSRMLS_DC);
PHPAPI char * mogilefs_file_to_mem(char *m_file, int *m_file_len TSRMLS_DC);
PHPAPI char * mogilefs_create_open(MogilefsSock *mogilefs_sock, const char * const, const char * const, int TSRMLS_DC);
PHPAPI int mogilefs_create_close(MogilefsSock *mogilefs_sock, const char * const m_key, const char * const m_class, const char * const close_request TSRMLS_DC);
PHPAPI int mogilefs_get_uri_path(const char * const url, php_url **p_url TSRMLS_DC);
PHPAPI void mogilefs_free_socket(MogilefsSock *mogilefs_sock);
/* }}} */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
