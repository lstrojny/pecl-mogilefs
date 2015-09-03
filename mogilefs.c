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

#define _GNU_SOURCE
#include <stdio.h>
#undef _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "ext/standard/url.h"
#include "ext/standard/php_string.h"
#include "zend_extensions.h"
#include "zend_interfaces.h"
#include "zend_exceptions.h"

#include "php_mogilefs.h"

#include <ne_socket.h>
#include <ne_session.h>
#include <ne_utils.h>
#include <ne_auth.h>
#include <ne_basic.h>

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION > 2) || PHP_MAJOR_VERSION > 5
# define MOGILEFS_ARG_INFO
#else
# define MOGILEFS_ARG_INFO static
#endif

/* {{{ arginfo */
MOGILEFS_ARG_INFO
ZEND_BEGIN_ARG_INFO(arginfo_MogileFs_isConnected, 0)
ZEND_END_ARG_INFO()

MOGILEFS_ARG_INFO
ZEND_BEGIN_ARG_INFO(arginfo_MogileFs_connect, 0)
	ZEND_ARG_INFO(0, host)
	ZEND_ARG_INFO(0, port)
	ZEND_ARG_INFO(0, domain)
	ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

MOGILEFS_ARG_INFO
ZEND_BEGIN_ARG_INFO(arginfo_MogileFs_setReadTimeout, 0)
	ZEND_ARG_INFO(0, readTimeout)
ZEND_END_ARG_INFO()

MOGILEFS_ARG_INFO
ZEND_BEGIN_ARG_INFO(arginfo_MogileFs_getReadTimeout, 0)
ZEND_END_ARG_INFO()

MOGILEFS_ARG_INFO
ZEND_BEGIN_ARG_INFO(arginfo_MogileFs_get, 0)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, pathcount)
ZEND_END_ARG_INFO()

MOGILEFS_ARG_INFO
ZEND_BEGIN_ARG_INFO(arginfo_MogileFs_fileInfo, 0)
	ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

MOGILEFS_ARG_INFO
ZEND_BEGIN_ARG_INFO(arginfo_MogileFs_getDomains, 0)
ZEND_END_ARG_INFO()

MOGILEFS_ARG_INFO
ZEND_BEGIN_ARG_INFO(arginfo_MogileFs_sleep, 0)
	ZEND_ARG_INFO(0, seconds)
ZEND_END_ARG_INFO()

MOGILEFS_ARG_INFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_MogileFs_put, 0, 0, 3)
	ZEND_ARG_INFO(0, filename)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, class)
	ZEND_ARG_INFO(0, file_only)
ZEND_END_ARG_INFO()

MOGILEFS_ARG_INFO
ZEND_BEGIN_ARG_INFO(arginfo_MogileFs_close, 0)
ZEND_END_ARG_INFO()

MOGILEFS_ARG_INFO
ZEND_BEGIN_ARG_INFO(arginfo_MogileFs_delete, 0)
	ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

MOGILEFS_ARG_INFO
ZEND_BEGIN_ARG_INFO(arginfo_MogileFs_rename, 0)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, destination)
ZEND_END_ARG_INFO()

MOGILEFS_ARG_INFO
ZEND_BEGIN_ARG_INFO(arginfo_MogileFs_isInDebuggingMode, 0)
ZEND_END_ARG_INFO()
/* }}} */

/* True global resources - no need for thread safety here */
static int le_mogilefs_sock;
static zend_class_entry *mogilefs_ce;
static zend_class_entry *mogilefs_exception_ce;

/* {{{ zend_function_entry */
static
zend_function_entry php_mogilefs_methods[] = {
	PHP_ME(MogileFs, __construct,		NULL,								ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, isConnected,		arginfo_MogileFs_isConnected,		ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, connect,			arginfo_MogileFs_connect,			ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, get,				arginfo_MogileFs_get,				ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, getDomains,		arginfo_MogileFs_getDomains,		ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, fileInfo,			arginfo_MogileFs_fileInfo,			ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, listKeys,			NULL,								ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, listFids,			NULL,								ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, getHosts,			NULL,								ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, getDevices,		NULL,								ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, sleep,				arginfo_MogileFs_sleep,				ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, stats,				NULL,								ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, replicate,			NULL,								ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, createDevice,		NULL,								ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, createDomain,		NULL,								ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, deleteDomain,		NULL,								ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, createClass,		NULL,								ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, updateClass,		NULL,								ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, deleteClass,		NULL,								ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, createHost,		NULL,								ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, updateHost,		NULL,								ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, deleteHost,		NULL,								ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, setWeight,			NULL,								ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, setState,			NULL,								ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, checker,			NULL,								ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, monitorRound,		NULL,								ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, put,				arginfo_MogileFs_put,				ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, close,				arginfo_MogileFs_close,				ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, delete,			arginfo_MogileFs_delete,			ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, rename,			arginfo_MogileFs_rename,			ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, setReadTimeout,	arginfo_MogileFs_setReadTimeout,	ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, getReadTimeout,	arginfo_MogileFs_getReadTimeout,	ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, isInDebuggingMode, arginfo_MogileFs_isInDebuggingMode,	ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
	/* Aliases */
	PHP_MALIAS(MogileFs, disconnect, close, arginfo_MogileFs_close, ZEND_ACC_PUBLIC)
	{NULL, NULL, NULL}
};
/* }}} */

zend_module_entry mogilefs_module_entry = {
#if ZEND_EXTENSION_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"mogilefs",
	NULL,
	PHP_MINIT(mogilefs),
	PHP_MSHUTDOWN(mogilefs),
	NULL,
	NULL,
	PHP_MINFO(mogilefs),
#if ZEND_MODULE_API_NO >= 20010901
	PHP_MOGILEFS_VERSION,
#endif
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_MOGILEFS
ZEND_GET_MODULE(mogilefs)
#endif
/* }}} */

static void mogilefs_destructor_mogilefs_sock(zend_rsrc_list_entry * rsrc TSRMLS_DC) /* {{{ */
{
	MogilefsSock *mogilefs_sock = (MogilefsSock *) rsrc->ptr;
	mogilefs_sock_disconnect(mogilefs_sock TSRMLS_CC);
	mogilefs_free_socket(mogilefs_sock);
}
/* }}} */

PHPAPI void mogilefs_free_socket(MogilefsSock *mogilefs_sock) /* {{{ */
{
	efree(mogilefs_sock->host);
	efree(mogilefs_sock->domain);
	efree(mogilefs_sock);
}
/* }}} */

PHP_MINIT_FUNCTION(mogilefs) /* {{{ */
{
	zend_class_entry mogilefs_class_entry;
	zend_class_entry mogilefs_exception_class_entry;
	
	ne_sock_init();
	INIT_CLASS_ENTRY(mogilefs_class_entry, "MogileFs", php_mogilefs_methods);
	mogilefs_ce = zend_register_internal_class(&mogilefs_class_entry TSRMLS_CC);

	INIT_CLASS_ENTRY(mogilefs_exception_class_entry, "MogileFsException", NULL);
	mogilefs_exception_ce = zend_register_internal_class_ex(
		&mogilefs_exception_class_entry,
		zend_exception_get_default(TSRMLS_C),
		NULL TSRMLS_CC
	);

	le_mogilefs_sock = zend_register_list_destructors_ex(
		mogilefs_destructor_mogilefs_sock,
		NULL,
		mogilefs_sock_name, module_number
	);
	return SUCCESS;
}
/* }}} */

PHP_MSHUTDOWN_FUNCTION(mogilefs) /* {{{ */
{
	ne_sock_exit();
	UNREGISTER_INI_ENTRIES();
	return SUCCESS;
}
/** }}} */

PHP_MINFO_FUNCTION(mogilefs) /* {{{ */
{
	php_info_print_table_start();
	php_info_print_table_header(2, "mogilefs support", "enabled");
	php_info_print_table_row(2, "Version", PHP_MOGILEFS_VERSION);
	php_info_print_table_row(2, "Revision", "$Id$");
	php_info_print_table_end();
}
/* }}} */

PHPAPI int mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAMETERS, char *result, int result_len) { /* {{{ */
	char *key_val, *last, *token, *splitted_key, *token_data, *cur_key = NULL, *k;
	int token_data_len;

	if ((token = estrndup(result, result_len)) == NULL) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Out of memory");
		return -1;
	}

	efree(result);

	array_init(return_value);

	for ((key_val = strtok_r(token, "&", &last)); key_val; (key_val = strtok_r(NULL, "&", &last))) {

		zval *data;

		if ((splitted_key = estrdup(key_val)) == NULL) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Out of memory");
			efree(token);
			return -1;
		}

		MAKE_STD_ZVAL(data);

		/* some return values can be null */
		if ((k = strtok(splitted_key, "=")) == NULL) {
			k = "\0";
		}
		/* some return values can be null */
		if ((k = strtok(NULL, "=")) == NULL) {
			k = "\0";
		}

		if (asprintf(&cur_key, "%s", splitted_key) < 0) {
			return -1;
		}

		token_data_len = spprintf(&token_data, 0, "%s", k);
		ZVAL_STRINGL(data, token_data, token_data_len, 1);
		add_assoc_zval(return_value, cur_key, data);

		efree(splitted_key);
		efree(token_data);
	}

	efree(token);
	return 0;
}
/* }}} */

PHPAPI MogilefsSock *mogilefs_sock_server_init(char *host, int host_len, unsigned short port, /* {{{ */
											char *domain, int domain_len, struct timeval connect_timeout) {
	MogilefsSock *mogilefs_sock;

	mogilefs_sock = emalloc(sizeof *mogilefs_sock);
	mogilefs_sock->host = emalloc(host_len + 1);
	mogilefs_sock->domain = emalloc(domain_len + 1);
	mogilefs_sock->stream = NULL;
	mogilefs_sock->status = MOGILEFS_SOCK_STATUS_DISCONNECTED;

	memcpy(mogilefs_sock->host, host, host_len);
	memcpy(mogilefs_sock->domain, domain, domain_len);
	mogilefs_sock->host[host_len] = '\0';
	mogilefs_sock->domain[domain_len] = '\0';

	mogilefs_sock->port = port;
	mogilefs_sock->connect_timeout = connect_timeout;
	mogilefs_sock->read_timeout.tv_sec = MOGILEFS_READ_TIMEOUT;
	mogilefs_sock->read_timeout.tv_usec = 0;

	return mogilefs_sock;
}
/* }}} */

PHPAPI int mogilefs_sock_disconnect(MogilefsSock *mogilefs_sock TSRMLS_DC) { /* {{{ */
	if (mogilefs_sock->stream == NULL) {
		return 0;
	}

	MOGILEFS_SOCK_WRITE(mogilefs_sock, "QUIT", 4);
	return mogilefs_sock_close(mogilefs_sock TSRMLS_CC);
}
/* }}} */

PHPAPI int mogilefs_sock_close(MogilefsSock *mogilefs_sock TSRMLS_DC) { /* {{{ */
	mogilefs_sock->status = MOGILEFS_SOCK_STATUS_DISCONNECTED;
	if (mogilefs_sock->stream != NULL) {
		php_stream_close(mogilefs_sock->stream);
	}
	mogilefs_sock->stream = NULL;
	return 1;
}
/* }}} */

PHPAPI int mogilefs_sock_connect(MogilefsSock *mogilefs_sock TSRMLS_DC) { /* {{{ */
	char *host = NULL, *hash_key = NULL, *errstr = NULL;
	int	host_len, err = 0;

	if (mogilefs_sock->stream != NULL) {
		mogilefs_sock_disconnect(mogilefs_sock TSRMLS_CC);
	}

	host_len = spprintf(&host, 0, "%s:%d", mogilefs_sock->host, mogilefs_sock->port);

	mogilefs_sock->stream = php_stream_xport_create(
		host,
		host_len,
		ENFORCE_SAFE_MODE,
		STREAM_XPORT_CLIENT | STREAM_XPORT_CONNECT,
		hash_key,
		&mogilefs_sock->connect_timeout,
		NULL,
		&errstr,
		&err
	);

	if (!mogilefs_sock->stream) {
		efree(host);
		efree(errstr);
		return -1;
	}
	efree(host);

	php_stream_auto_cleanup(mogilefs_sock->stream);
	php_stream_set_option(mogilefs_sock->stream, PHP_STREAM_OPTION_READ_TIMEOUT, 0, &mogilefs_sock->read_timeout);
	php_stream_set_option(mogilefs_sock->stream, PHP_STREAM_OPTION_WRITE_BUFFER, PHP_STREAM_BUFFER_NONE, NULL);
	mogilefs_sock->status = MOGILEFS_SOCK_STATUS_CONNECTED;
	return 0;
}
/* }}} */

PHPAPI int mogilefs_sock_server_open(MogilefsSock *mogilefs_sock, int force_connect TSRMLS_DC) { /* {{{ */
	switch (mogilefs_sock->status) {
		case MOGILEFS_SOCK_STATUS_DISCONNECTED:
			return mogilefs_sock_connect(mogilefs_sock TSRMLS_CC);

		case MOGILEFS_SOCK_STATUS_CONNECTED:
			return 0;

		case MOGILEFS_SOCK_STATUS_UNKNOWN:
			if (force_connect > 0 && mogilefs_sock_connect(mogilefs_sock TSRMLS_CC) < 0) {
				return -1;
			}
			mogilefs_sock->status = MOGILEFS_SOCK_STATUS_CONNECTED;
			return 0;
	}
	return -1;
}
/* }}} */

PHPAPI int mogilefs_sock_get(zval *id, MogilefsSock **mogilefs_sock TSRMLS_DC) { /* {{{ */
	zval **socket;
	int resource_type;

	if (Z_TYPE_P(id) != IS_OBJECT || zend_hash_find(Z_OBJPROP_P(id), "socket", sizeof("socket"), (void **) &socket) == FAILURE) {
		return -1;
	}

	*mogilefs_sock = (MogilefsSock *) zend_list_find(Z_LVAL_PP(socket), &resource_type);

	if (!*mogilefs_sock || resource_type != le_mogilefs_sock) {
		return -1;
	}

	return Z_LVAL_PP(socket);
}
/* }}} */

PHPAPI int mogilefs_sock_eof(MogilefsSock *mogilefs_sock TSRMLS_DC) { /* {{{ */
	if (!mogilefs_sock || mogilefs_sock->stream == NULL) {
		mogilefs_sock_close(mogilefs_sock TSRMLS_CC);
		zend_throw_exception(mogilefs_exception_ce, "Lost tracker connection", 0 TSRMLS_CC);
		return 1;
	}
	if (php_stream_eof(mogilefs_sock->stream)) {
		/* close socket but avoid writing on it again */
		mogilefs_sock_close(mogilefs_sock TSRMLS_CC);
		zend_throw_exception(mogilefs_exception_ce, "Lost tracker connection", 0 TSRMLS_CC);
		return 1;
	}
	return 0;
}
/* }}} */
	
PHPAPI int mogilefs_sock_write(MogilefsSock *mogilefs_sock, char *cmd, unsigned int cmd_len, short free_cmd TSRMLS_DC) { /* {{{ */
	int retval = 0;

#ifdef MOGILEFS_DEBUG
	php_printf("REQUEST: %s", cmd);
#endif

	if (mogilefs_sock_eof(mogilefs_sock TSRMLS_CC)) {
		retval = -1;
	} else if (php_stream_write(mogilefs_sock->stream, cmd, cmd_len) != cmd_len) {
		retval = -1;
	}

	if (free_cmd) {
		efree(cmd);
	}

	return retval;
}
/* }}} */

PHPAPI char *mogilefs_sock_read(MogilefsSock *mogilefs_sock, int *buf_len TSRMLS_DC) { /* {{{ */
	char *outbuf, *p, *message, *message_clean, *retbuf;
	size_t outbuf_len;

	if (mogilefs_sock_eof(mogilefs_sock TSRMLS_CC)) {
		return NULL;
	}

	outbuf = php_stream_get_line(mogilefs_sock->stream, NULL, MOGILEFS_MAX_MESSAGE_SIZE, &outbuf_len); /* OK / ERR */
	if (!outbuf) {
		zend_throw_exception(mogilefs_exception_ce, "Read returned no data", 0 TSRMLS_CC);
		return NULL;
	}

	p = outbuf + outbuf_len - 2;
	if (p) *p = '\0';

#ifdef MOGILEFS_DEBUG
	php_printf("RESPONSE: %s\n", outbuf);
#endif

	outbuf_len = php_url_decode(outbuf, outbuf_len);

	if (strncmp(outbuf, "OK", 2) != 0) {
		*buf_len = 0;

		message = php_trim(outbuf, outbuf_len, NULL, 0, NULL, 3 TSRMLS_CC);

#ifdef MOGILEFS_DEBUG
		php_printf("ERROR: %s\n", message);
#endif

		message_clean = malloc(strlen(message) + 1);
		/** Extract error message from "ERR <code> <message>" */
		if ((p = strchr(message, ' ')) && (p = strchr(p + 1, ' '))) {
			strcpy(message_clean, p + 1);
		} else {
			strcpy(message_clean, message);
		}

		zend_throw_exception(mogilefs_exception_ce, message_clean, 0 TSRMLS_CC);

		efree(outbuf);
		efree(message);

		return NULL;
	}

	*buf_len = outbuf_len - 2;
	retbuf = estrndup(outbuf + 3, *buf_len);

	efree(outbuf);

	return retbuf; 
}
/* }}} */

PHPAPI char *mogilefs_create_open(MogilefsSock *mogilefs_sock, const char * const key,	const char * const class, int multi_dest TSRMLS_DC) /* {{{ */
{
	int request_len, response_len;
	char *request = NULL, *response = NULL;

	request_len = spprintf(
		&request,
		0,
		"CREATE_OPEN domain=%s&key=%s&class=%s&multi_dest=%d\r\n",
		mogilefs_sock->domain,
		key,
		class,
		multi_dest
	);

	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		return NULL;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		return NULL;
	}

	return response;
}
/* }}} */

PHPAPI int mogilefs_create_close(MogilefsSock *mogilefs_sock, const char * const key, /* {{{ */
						 const char * const class, const char * const close_request TSRMLS_DC)
{
	int request_len, response_len;
	char *request = NULL, *response;

	request_len = spprintf(&request, 0, "CREATE_CLOSE domain=%s&key=%s&class=%s&%s\r\n",
							mogilefs_sock->domain, key, class, close_request);
	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		return -1;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		return -1;
	}

	efree(response);
	return 0;
}
/* }}} */

PHPAPI int mogilefs_get_uri_path(const char * const url, php_url **p_url TSRMLS_DC) { /* {{{ */
	char *key_val, *last, *token, *splitted_key, *splitted_uri, *splitted;
	int splitted_uri_len = 0;
	signed int ret = -2;
	token = estrdup(url);

	for ((key_val = strtok_r(token, "&", &last)); key_val; (key_val = strtok_r(NULL, "&", &last))) {
		if ((splitted_key = estrdup(key_val)) == NULL) {
			ret = -1;
			break;
		}
		if ((splitted = strtok(splitted_key, "=")) == NULL) {
			efree(splitted_key);
			ret = -1;
			break;
		}
		if (strcmp("path", splitted) != 0) {
			efree(splitted_key);
			continue;
		}
		if ((splitted = strtok(NULL, "=")) == NULL) {
			efree(splitted);
			efree(splitted_key);
			ret = -1;
			break;
		}
		if ((splitted_uri_len = spprintf(&splitted_uri, strlen(splitted), "%s", splitted)) == 0) {
			efree(splitted);
			efree(splitted_uri);
			efree(splitted_key);
			ret = -1;
			break;
		}
		*p_url = (php_url *) php_url_parse_ex(splitted_uri, splitted_uri_len);
		ret = 0;
		efree(splitted_key);
		efree(splitted_uri);
		break;
	}
	efree(token);
	return ret;
} /* }}} */

PHPAPI void mogilefs_get_default_domain(MogilefsSock *mogilefs_sock, char **domain) /* {{{ */
{
	if (*domain == NULL || strcmp(*domain, "\0") == 0 || strlen(*domain) == 0) {
		*domain = mogilefs_sock->domain;
	}
} /* }}} */

/* {{{ proto Mogilefs MogileFs::__construct()
	Create new MogileFs instance */
PHP_METHOD(MogileFs, __construct)
{
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		return;
	}
}
/* }}} */

/* {{{ proto bool MogileFs::connect(string host, string port, string domain [, int timeout])
	Initialize a new MogileFs Session */
PHP_METHOD(MogileFs, connect)
{
	int host_len, domain_len, id;
	char *host = NULL, *domain = NULL;
	unsigned long port, connect_timeout_conv;
	double connect_timeout = MOGILEFS_CONNECT_TIMEOUT;
	struct timeval tv;
	MogilefsSock *mogilefs_sock = NULL;
	zval *object;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(),
		"Osls|d", &object, mogilefs_ce, &host, &host_len, &port,
		&domain, &domain_len, &connect_timeout) == FAILURE) {

		return;
	}


	if (connect_timeout < 0 || connect_timeout > (double)INT_MAX) {
		zend_throw_exception(mogilefs_exception_ce, "Invalid timeout", 0 TSRMLS_CC);
		RETURN_FALSE;
	}

	connect_timeout_conv = (int)(connect_timeout * 1000);
	tv.tv_sec = connect_timeout_conv / 1000;
	tv.tv_usec = connect_timeout_conv % 1000;


	mogilefs_sock = mogilefs_sock_server_init(host, host_len, port, domain, domain_len, tv);
	if (mogilefs_sock_server_open(mogilefs_sock, 1 TSRMLS_CC) < 0) {
		mogilefs_free_socket(mogilefs_sock);
		zend_throw_exception_ex(
			mogilefs_exception_ce,
			0 TSRMLS_CC,
			"Can't connect to %s:%d",
			host,
			port
		);
		RETURN_FALSE;
	}

	id = zend_list_insert(mogilefs_sock, le_mogilefs_sock TSRMLS_CC);
	add_property_resource(object, "socket", id);
	RETURN_TRUE;
}

/* }}} */

/* {{{ proto string MogileFs::close()
	Close a MogileFs Session */
PHP_METHOD(MogileFs, close)
{
	zval *object;
	MogilefsSock *mogilefs_sock = NULL;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "O",
		&object, mogilefs_ce) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}

	if (mogilefs_sock_disconnect(mogilefs_sock TSRMLS_CC)) {
		RETURN_TRUE;
	}
	RETURN_FALSE;
}

/* }}} */

/* {{{ proto bool MogileFs::put(string file, string key, string class [, bool use_file = true [, bool multi_dest]])
	Put a file to the MogileFs tracker */
PHP_METHOD(MogileFs, put)
{
	zval *object;
	MogilefsSock *mogilefs_sock;
	php_url *url;
	ne_session *sess;
	ne_request *req;
	int multi_dest = 1,
		use_file = 1,
		key_len,
		class_len,
		file_buffer_len,
		filename_len,
		ret,
		alloc_url = 0,
		fd = 0;
	char *key = NULL,
		*class = NULL,
		*file_buffer,
		*filename,
		*close_request;
	FILE *f;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(),
				"Osss|bl", &object, mogilefs_ce,
				&filename, &filename_len, &key, &key_len,
				&class, &class_len, &use_file, &multi_dest) == FAILURE) {

			return;
	}

	multi_dest = 0;

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to MogileFS tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}

	if ((close_request = mogilefs_create_open(mogilefs_sock, key, class, multi_dest TSRMLS_CC)) == NULL) {
		zend_throw_exception(mogilefs_exception_ce, "Could not open CREATE_CLOSE connection", 0 TSRMLS_CC);
		RETVAL_FALSE;
		goto end;
	}

	if (mogilefs_get_uri_path(close_request, &url TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not retrieve MogileFS path", 0 TSRMLS_CC);
		RETVAL_FALSE;
		goto end;
	}

	alloc_url = 1;

	if (url->port == 0) {
		url->port = ne_uri_defaultport(url->scheme);
	}
	if (url->scheme == NULL) {
		url->scheme = "http";
	}

	if ((sess = ne_session_create(url->scheme, url->host, url->port)) == NULL) {
		zend_throw_exception(mogilefs_exception_ce, "Could not open WebDAV connection", 0 TSRMLS_CC);
		RETVAL_FALSE;
		goto end;
	}

	ne_set_connect_timeout(sess, (int) mogilefs_sock->connect_timeout.tv_sec);
	ne_set_read_timeout(sess, (int) mogilefs_sock->read_timeout.tv_sec);

	if (use_file) {
		f = php_stream_open_wrapper_as_file(filename, "rb", USE_PATH | ENFORCE_SAFE_MODE, NULL);
		if (f != NULL) {
			fd = fileno(f);
			ret = ne_put(sess, url->path, fd);
			close(fd);
		} else {
			zend_throw_exception(mogilefs_exception_ce, "Could not open file", 0 TSRMLS_CC);
			RETVAL_FALSE;
			goto end;
		}
	} else {
		file_buffer = filename;
		file_buffer_len = filename_len;
		req = ne_request_create(sess, "PUT", url->path);
		ne_set_request_body_buffer(req, file_buffer, file_buffer_len);
		ret = ne_request_dispatch(req);
		ne_request_destroy(req);
	}

	ne_session_destroy(sess);

	if (ret != NE_OK) {
		zend_throw_exception_ex(mogilefs_exception_ce, 0 TSRMLS_CC, "%s", ne_get_error(sess));
		RETVAL_FALSE;
		goto end;
	}

	if (mogilefs_create_close(mogilefs_sock, key, class, close_request TSRMLS_CC) < 0) {
		RETVAL_FALSE;
		goto end;
	}

	RETVAL_TRUE;

end:
	if (close_request) {
		efree(close_request);
	}
	if (alloc_url) {
		php_url_free(url);
	}
}
/* }}} */

/* {{{ proto string MogileFs::get(string key, integer pathcount)
	Get MogileFs path */
PHP_METHOD(MogileFs, get)
{
	zval *object;
	MogilefsSock *mogilefs_sock;
	char *key = NULL, *request, *response;
	int key_len, pathcount = 2, request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Os|l",
									&object, mogilefs_ce,
									&key, &key_len, &pathcount) == FAILURE) {
			return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}
	request_len = spprintf(&request, 0, "GET_PATHS domain=%s&key=%s&pathcount=%d\r\n", mogilefs_sock->domain, key, pathcount);
	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}
	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
}

/* }}} */

/* {{{ proto bool MogileFs::delete(string key)
	Delete a MogileFs file */
PHP_METHOD(MogileFs, delete)
{
	zval *object;
	MogilefsSock *mogilefs_sock;
	char *key = NULL, *request, *response;
	int key_len, request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Os",
		&object, mogilefs_ce, &key, &key_len) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}

	request_len = spprintf(&request, 0, "DELETE domain=%s&key=%s\r\n", mogilefs_sock->domain, key);
	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	efree(response);
	RETURN_TRUE;
}

/* }}} */

/* {{{ proto string MogileFs::rename(string src, string dest)
	Move a MogileFs file */
PHP_METHOD(MogileFs, rename)
{
	zval *object;
	MogilefsSock *mogilefs_sock;
	char *src_key = NULL, *dest_key = NULL, *request, *response;
	int src_key_len, dest_key_len, request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Oss",
			&object, mogilefs_ce, &src_key, &src_key_len,
			&dest_key, &dest_key_len) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}
	request_len = spprintf(&request, 0, "RENAME domain=%s&from_key=%s&to_key=%s\r\n", mogilefs_sock->domain, src_key, dest_key);
	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}
	efree(response);
	RETURN_TRUE;
}

/* }}} */


/* {{{ proto array MogileFs::fileInfo(string key)
	Get MogileFs fileInfo */
PHP_METHOD(MogileFs, fileInfo)
{
	zval *object;
	MogilefsSock *mogilefs_sock;
	char *key = NULL, *request, *response;
	int key_len, request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Os",
			&object, mogilefs_ce, &key, &key_len) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}

	request_len = spprintf(&request, 0, "FILE_INFO domain=%s&key=%s\r\n", mogilefs_sock->domain, key);
	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
}

/* }}} */



/* {{{ proto array MogileFs::getDomains()
	Get MogileFs domains */
PHP_METHOD(MogileFs, getDomains)
{
	zval *object;
	MogilefsSock *mogilefs_sock;
	char *request, *response;
	int	request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "O",
			&object, mogilefs_ce) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}
	request_len = spprintf(&request, 0, "GET_DOMAINS\r\n");
	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}
	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
}

/* }}} */

/* {{{ proto array MogileFs::listKeys()
	Get MogileFs file keys */
PHP_METHOD(MogileFs, listKeys)
{
	zval *object;
	MogilefsSock *mogilefs_sock;
	char *prefix = NULL, *after = NULL, *request, *response;
	long limit = 1000;
	int prefix_len, after_len, request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Oss|l",
		&object, mogilefs_ce, &prefix, &prefix_len,
		&after, &after_len, &limit) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}


	request_len = spprintf(
		&request,
		0,
		"LIST_KEYS domain=%s&prefix=%s&after=%s&limit=%d\r\n",
		mogilefs_sock->domain,
		prefix,
		after,
		(int) limit
	);

	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}
	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ proto array MogileFs::listFids()
	Get MogileFs file ids */
PHP_METHOD(MogileFs, listFids)
{
	zval *object = getThis();
	MogilefsSock *mogilefs_sock;
	char *to = "100", *from = "0", *request, *response;
	int	to_len, from_len, request_len, response_len;

	if (object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O|ss", &object,
			mogilefs_ce, &from, &from_len, &to, &to_len) == FAILURE) {
			RETURN_FALSE;
		}

	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|ss",
															&from, &from_len, &to, &to_len) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}

	request_len = spprintf(&request, 0, "LIST_FIDS domain=%s&from=%s&to=%s\r\n", mogilefs_sock->domain, from, to);

	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
}


/* }}} */

/* {{{ proto array MogileFs::getHosts()
	Get MogileFs hosts */
PHP_METHOD(MogileFs, getHosts)
{
	zval *object = getThis();
	MogilefsSock *mogilefs_sock;
	char *request, *response;
	int request_len, response_len;

	if (object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &object,
									mogilefs_ce) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}

	request_len = spprintf(&request, 0, "GET_HOSTS domain=%s\r\n", mogilefs_sock->domain);

	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
}


/* }}} */

/* {{{ proto array MogileFs::getDevices()
	Get MogileFs devices */
PHP_METHOD(MogileFs, getDevices)
{
	zval *object = getThis();
	MogilefsSock *mogilefs_sock;
	char *request, *response;
	int request_len, response_len;

	if(object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &object,
									mogilefs_ce) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}

	request_len = spprintf(&request, 0, "GET_DEVICES domain=%s\r\n", mogilefs_sock->domain);

	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ proto bool MogileFs::sleep(ingeter duration)
 */
PHP_METHOD(MogileFs, sleep)
{
	zval *object;
	MogilefsSock *mogilefs_sock;
	char *request, *response;
	long duration;
	int	request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "O|l", &object,
		mogilefs_ce, &duration) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}

	request_len = spprintf(&request, 0, "SLEEP domain=%s&duration=%d\r\n", mogilefs_sock->domain, (int) duration);

	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}
	efree(response);
	RETURN_TRUE;
}

/* }}} */

/* {{{ proto array MogileFs::stats([bool all])
 */
PHP_METHOD(MogileFs, stats)
{
	zval *object = getThis();
	MogilefsSock *mogilefs_sock;
	char *all = "1", *request, *response;
	int	all_len, request_len, response_len;

	if(object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O|s", &object,
									mogilefs_ce, &all, &all_len) == FAILURE) {
			RETURN_FALSE;
		}

	}else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|s",
															&all, &all_len) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}

	request_len = spprintf(&request, 0, "STATS domain=%s&all=%s\r\n", mogilefs_sock->domain, all);

	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}
	if(mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
}

/* }}} */

/* {{{ proto array MogileFs::replicate()
 */
PHP_METHOD(MogileFs, replicate)
{
	zval *object = getThis();
	MogilefsSock *mogilefs_sock;
	char	*request, *response;
	int	 request_len, response_len;

	if(object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &object,
									mogilefs_ce) == FAILURE) {
			RETURN_FALSE;
		}

	}
	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}

	request_len = spprintf(&request, 0, "REPLICATE_NOW domain=%s\r\n", mogilefs_sock->domain);

	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
}

/* }}} */

/* {{{ proto bool MogileFs::createDevice(string devid, string status)
 */
PHP_METHOD(MogileFs, createDevice)
{
	zval *object = getThis();
	MogilefsSock *mogilefs_sock;
	char *status, *devid, *request, *response;
	int	status_len, devid_len, request_len, response_len;

	if(object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Oss", &object,
									mogilefs_ce, &devid, &devid_len, &status, &status_len ) == FAILURE) {
			RETURN_FALSE;
		}
	}else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
																												&devid, &devid_len, &status, &status_len) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}

	request_len = spprintf(&request, 0, "CREATE_DEVICE domain=%s&status=%s&devid=%s\r\n", mogilefs_sock->domain, status, devid);

	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ proto bool MogileFs::createDomain(string domain)
 */
PHP_METHOD(MogileFs, createDomain)
{
	zval *object;
	MogilefsSock *mogilefs_sock;
	char *domain, *request, *response;
	int	domain_len, request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Os",
		&object, mogilefs_ce, &domain, &domain_len) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}

	request_len = spprintf(&request, 0, "CREATE_DOMAIN domain=%s\r\n", domain);

	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ proto bool MogileFs::deleteDomain(string domain)
 */
PHP_METHOD(MogileFs, deleteDomain)
{
	zval *object;
	MogilefsSock *mogilefs_sock;
	char *domain, *request, *response;
	int	domain_len, request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Os",
		&object, mogilefs_ce, &domain, &domain_len) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}

	request_len = spprintf(&request, 0, "DELETE_DOMAIN domain=%s\r\n", domain);

	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
}

/* }}} */

/* {{{ proto bool MogileFs::createClass(string domain, string class, string mindevcount)
 */
PHP_METHOD(MogileFs, createClass)
{
	zval *object;
	MogilefsSock *mogilefs_sock;
	char *domain = NULL, *class, *request, *response;
	int	domain_len, class_len, mindevcount, request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Ossl",
		&object, mogilefs_ce, &domain, &domain_len,
		&class, &class_len, &mindevcount) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}

	mogilefs_get_default_domain(mogilefs_sock, &domain);

	request_len = spprintf(
		&request,
		0,
		"CREATE_CLASS domain=%s&class=%s&mindevcount=%d\r\n",
		domain,
		class,
		mindevcount
	);

	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
}

/* }}} */

/* {{{ proto bool MogileFs::updateClass(string domain, string class, string mindevcount)
 */
PHP_METHOD(MogileFs, updateClass)
{
	zval *object;
	MogilefsSock *mogilefs_sock;
	char *domain = NULL, *class, *request, *response;
	int	domain_len, class_len, request_len, response_len;
	long mindevcount;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Ossl",
		&object, mogilefs_ce, &domain, &domain_len,
		&class, &class_len, &mindevcount) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}

	mogilefs_get_default_domain(mogilefs_sock, &domain);

	request_len = spprintf(
		&request,
		0,
		"UPDATE_CLASS domain=%s&class=%s&mindevcount=%d&update=1\r\n",
		domain,
		class,
		(int) mindevcount
	);

	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
}

/* }}} */

/* {{{ proto bool MogileFs::deleteClass(string domain, string class)
 */
PHP_METHOD(MogileFs, deleteClass)
{
	zval *object;
	MogilefsSock *mogilefs_sock;
	char *domain = NULL, *class, *request, *response;
	int	domain_len, class_len, request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Oss",
		&object, mogilefs_ce, &domain, &domain_len,
		&class, &class_len) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}

	mogilefs_get_default_domain(mogilefs_sock, &domain);

	request_len = spprintf(&request, 0, "DELETE_CLASS domain=%s&class=%s\r\n", domain, class);

	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
}

/* }}} */

/* {{{ proto array MogileFs::createHost(string domain, string host, string ip, int port)
 */
PHP_METHOD(MogileFs, createHost)
{
	zval *object = getThis();
	MogilefsSock *mogilefs_sock;
	char *host, *ip, *port, *request, *response;
	int	host_len, ip_len, port_len, request_len, response_len;

	if (object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Osss", &object,
									mogilefs_ce, &host, &host_len, &ip, &ip_len, &port, &port_len) == FAILURE) {
			RETURN_FALSE;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
									&host, &host_len, &ip, &ip_len, &port, &port_len) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}
	request_len = spprintf(&request, 0, "CREATE_HOST domain=%s&host=%s&ip=%s&port=%s\r\n", mogilefs_sock->domain, host, ip, port);
	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
}

/* }}} */

/* {{{ proto bool MogileFs::updateHost(string hostname, string ip, string port, string status[dead, alive])
 */
PHP_METHOD(MogileFs, updateHost)
{
	zval *object = getThis();
	MogilefsSock *mogilefs_sock;
	char *host, *ip, *port, *status = "alive", *request, *response;
	int	host_len, ip_len, port_len, status_len, request_len, response_len;

	if (object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Osss|s", &object,
				mogilefs_ce, &host, &host_len, &ip, &ip_len, &port, &port_len, &status, &status_len) == FAILURE) {
			RETURN_FALSE;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss|s",
									&host, &host_len, &ip, &ip_len, &port, &port_len, &status, &status_len) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (!strcmp("alive", status) && !strcmp("dead", status)) {
		zend_throw_exception(mogilefs_exception_ce, "Invalid connection status", 0 TSRMLS_CC);
		RETURN_FALSE;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}
	request_len = spprintf(&request, 0, "UPDATE_HOST domain=%s&host=%s&ip=%s&port=%s&status=%s&update=1\r\n", mogilefs_sock->domain, host, ip, port, status);

	if(MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
}

/* }}} */

/* {{{ proto bool MogileFs::deleteHost(string host)
 */
PHP_METHOD(MogileFs, deleteHost)
{
	zval *object = getThis();
	MogilefsSock *mogilefs_sock;
	char *host,	*request, *response;
	int host_len, request_len, response_len;

	if (object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Os", &object,
									mogilefs_ce, &host, &host_len) == FAILURE) {
			RETURN_FALSE;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
									&host, &host_len) == FAILURE) {
			RETURN_FALSE;
		}
	}


	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}
	request_len = spprintf(&request, 0, "DELETE_HOST domain=%s&host=%s\r\n", mogilefs_sock->domain, host);

	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}

	RETURN_TRUE;
}

/* }}} */

/* {{{ proto array MogileFs::setWeight(string host, string device, int weight)
 */
PHP_METHOD(MogileFs, setWeight)
{
	zval *object = getThis();
	MogilefsSock *mogilefs_sock;
	char *host,	*device, *weight,	*request, *response;
	int	host_len, device_len, weight_len, request_len, response_len;

	if (object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Osss", &object,
						mogilefs_ce, &host, &host_len, &device, &device_len, &weight, &weight_len) == FAILURE) {
			RETURN_FALSE;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
												&host, &host_len, &device, &device_len, &weight, &weight_len) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}
	request_len = spprintf(&request, 0, "SET_WEIGHT domain=%s&host=%s&device=%s&weight=%s\r\n", mogilefs_sock->domain, host, device, weight);

	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
	RETURN_TRUE;
}

/* }}} */

/* {{{ proto array MogileFs::setState(string host, string device, string state)
 */
PHP_METHOD(MogileFs, setState)
{
	zval *object = getThis();
	MogilefsSock *mogilefs_sock;
	char *host,	*device, *state = "alive",	*request, *response;
	int	host_len, device_len, state_len, request_len, response_len;

	if (object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Osss", &object,
						mogilefs_ce, &host, &host_len, &device, &device_len, &state, &state_len) == FAILURE) {
			RETURN_FALSE;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
								&host, &host_len, &device, &device_len, &state, &state_len) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (!strcmp("alive", state) && !strcmp("dead", state)) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid state");
		RETURN_FALSE;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}
	request_len = spprintf(&request, 0, "SET_STATE domain=%s&host=%s&device=%s&state=%s\r\n", mogilefs_sock->domain, host, device, state);

	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
	RETURN_TRUE;
}

/* }}} */

/* {{{ proto array MogileFs::checker(string disable, string level)
 */
PHP_METHOD(MogileFs, checker)
{
	zval *object = getThis();
	MogilefsSock *mogilefs_sock;
	char *disable="off", *level="1", *request, *response;
	int	disable_len, level_len, request_len, response_len;

	if (object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O|ss", &object,
									mogilefs_ce, &disable, &disable_len, &level, &level_len) == FAILURE) {
			RETURN_FALSE;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|ss",
									&disable, &disable_len, &level, &level_len) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if(!strcmp("on", disable) && !strcmp("off", disable))
	{
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid parameter, first parameter must be 'off' or 'on' ");
		RETURN_FALSE;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}
	request_len = spprintf(&request, 0, "CHECKER domain=%s&disable=%s&level=%s\r\n", mogilefs_sock->domain, disable, level);

	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
	RETURN_TRUE;
}

/* }}} */

/* {{{ proto array MogileFs::monitorRound()
 */
PHP_METHOD(MogileFs, monitorRound)
{
	zval *object;
	MogilefsSock *mogilefs_sock;
	char *request, *response;
	int	request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "O",
		&object, mogilefs_ce) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		zend_throw_exception(mogilefs_exception_ce, "Could not connect to tracker", 0 TSRMLS_CC);
		RETURN_FALSE;
	}

	request_len = spprintf(
		&request,
		0,
		"DO_MONITOR_ROUND domain=%s\r\n",
		mogilefs_sock->domain
	);

	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool MogileFs::isConnected()
 */
PHP_METHOD(MogileFs, isConnected)
{
	zval *object;
	MogilefsSock *mogilefs_sock;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "O",
		&object, mogilefs_ce) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}

	RETURN_BOOL(mogilefs_sock->status == MOGILEFS_SOCK_STATUS_CONNECTED);
}
/* }}} */

/* {{{ proto bool MogileFs::isInDebuggingMode() */
PHP_METHOD(MogileFs, isInDebuggingMode)
{
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		return;
	}

#ifdef MOGILEFS_DEBUG
	RETURN_TRUE;
#else
	RETURN_FALSE;
#endif
}
/* }}} */


/* {{{ proto void MogileFs::setReadTimeout(float readTimeout) */
PHP_METHOD(MogileFs, setReadTimeout)
{
	zval *object;
	MogilefsSock *mogilefs_sock = NULL;
	unsigned long read_timeout_conv;
	double read_timeout = 0;
	struct timeval tv;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Od",
	    &object, mogilefs_ce, &read_timeout) == FAILURE) {

	    return;
	}
	
	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {

		zend_throw_exception(mogilefs_exception_ce, "No connection established. Call connect() first", 0 TSRMLS_CC);
	    return;
	}

	read_timeout_conv = (int)(read_timeout * 1000);

	tv.tv_sec = read_timeout_conv / 1000;
	tv.tv_usec = read_timeout_conv % 1000;

	mogilefs_sock->read_timeout = tv;

	RETURN_NULL();
}
/* }}} */

/** {{ proto float MogileFs::getReadTimeout(float readTimeout) */
PHP_METHOD(MogileFs, getReadTimeout)
{
	zval *object;
	MogilefsSock *mogilefs_sock = NULL;
	double read_timeout;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "O",
		&object, mogilefs_ce) == FAILURE) {

		return;
	}


	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {

		RETURN_DOUBLE(MOGILEFS_READ_TIMEOUT);
	}

	read_timeout = (float)((mogilefs_sock->read_timeout.tv_sec * 1000) + mogilefs_sock->read_timeout.tv_usec) / 1000;

	RETURN_DOUBLE(read_timeout);
}
/* }}} */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
