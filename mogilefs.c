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
ZEND_BEGIN_ARG_INFO(arginfo_MogileFs_get, 0)
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
ZEND_BEGIN_ARG_INFO(arginfo_MogileFs_put, 0)
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
static zend_class_entry *mogilefs_class_entry_ptr;
static zend_class_entry *mogilefs_exception_class_entry_ptr;

/* {{{ zend_function_entry */
static
zend_function_entry php_mogilefs_methods[] = {
	PHP_ME(MogileFs, isConnected,		arginfo_MogileFs_isConnected,		ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, connect,			arginfo_MogileFs_connect,			ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, get,				arginfo_MogileFs_get,				ZEND_ACC_PUBLIC)
	PHP_ME(MogileFs, getDomains,		arginfo_MogileFs_getDomains,		ZEND_ACC_PUBLIC)
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
	ne_sock_init();
	zend_class_entry mogilefs_class_entry;
	INIT_CLASS_ENTRY(mogilefs_class_entry, "MogileFs", php_mogilefs_methods);
	mogilefs_class_entry_ptr = zend_register_internal_class(&mogilefs_class_entry TSRMLS_CC);

	zend_class_entry mogilefs_exception_class_entry;
	INIT_CLASS_ENTRY(mogilefs_exception_class_entry, "MogileFsException", NULL);
	mogilefs_exception_class_entry_ptr = zend_register_internal_class_ex(
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

PHPAPI int mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAMETERS, const char * const result, int result_len) { /* {{{ */
	char *l_key_val, *last, *token, *splitted_key, *t_data, *cur_key = NULL, *k;
	int t_data_len;

	if ((token = estrndup(result, result_len)) == NULL) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Out of memory");
		return -1;
	}

	array_init(return_value);

	for ((l_key_val = strtok_r(token, "&", &last)); l_key_val;
		(l_key_val = strtok_r(NULL, "&", &last))) {

		zval *data;

		if ((splitted_key = estrdup(l_key_val)) == NULL) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Out of memory");
			efree(token);
			return -1;
		}
		MAKE_STD_ZVAL(data);
		if ((k = strtok(splitted_key, "=")) == NULL) {
			 // some return values can be null
			 // return -1;
			 k = "\0";
		}
		asprintf(&cur_key, "%s", splitted_key);
		if ((k = strtok(NULL, "=")) == NULL) {
			// some return values can be null
			// return -1;
			 k = "\0";
		}
		t_data_len = spprintf(&t_data, 0, "%s", k);
		ZVAL_STRINGL(data, t_data, t_data_len, 1);
		add_assoc_zval(return_value, cur_key, data);
		efree(splitted_key);
		efree(t_data);
	}
	efree(token);
	return 0;
}
/* }}} */

PHPAPI MogilefsSock *mogilefs_sock_server_init(char *host, int host_len, unsigned short port, /* {{{ */
										char *domain, int domain_len, long timeout) {
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
	mogilefs_sock->timeout = timeout;

	return mogilefs_sock;
}
/* }}} */

PHPAPI int mogilefs_sock_disconnect(MogilefsSock *mogilefs_sock TSRMLS_DC) { /* {{{ */
	if (mogilefs_sock->stream == NULL) {
		return 0;
	}

	MOGILEFS_SOCK_WRITE(mogilefs_sock, "QUIT", 4);
	mogilefs_sock->status = MOGILEFS_SOCK_STATUS_DISCONNECTED;
	php_stream_close(mogilefs_sock->stream);
	mogilefs_sock->stream = NULL;
	return 1;
}
/* }}} */

PHPAPI int mogilefs_sock_connect(MogilefsSock *mogilefs_sock TSRMLS_DC) { /* {{{ */
	struct timeval tv;
	char *host = NULL, *hash_key = NULL, *errstr = NULL;
	int	host_len, err = 0;

	if (mogilefs_sock->stream != NULL) {
		mogilefs_sock_disconnect(mogilefs_sock TSRMLS_CC);
	}

	tv.tv_sec = mogilefs_sock->timeout;
	tv.tv_usec = 0;

	host_len = spprintf(&host, 0, "%s:%d", mogilefs_sock->host, mogilefs_sock->port);

	mogilefs_sock->stream = php_stream_xport_create(
		host,
		host_len,
		ENFORCE_SAFE_MODE,
		STREAM_XPORT_CLIENT | STREAM_XPORT_CONNECT,
		hash_key,
		&tv,
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
	php_stream_set_option(mogilefs_sock->stream, PHP_STREAM_OPTION_READ_TIMEOUT, 0, &tv);
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

PHPAPI int mogilefs_sock_write(MogilefsSock *mogilefs_sock, char *cmd, int cmd_len, short free_cmd TSRMLS_DC) { /* {{{ */
	int retval = 0;

#ifdef MOGILEFS_DEBUG
	php_printf("REQUEST: %s", cmd);
#endif

	if (php_stream_write(mogilefs_sock->stream, cmd, cmd_len) != cmd_len) {
		retval = -1;
	}

	if (free_cmd) {
		efree(cmd);
	}

	return retval;
}
/* }}} */

PHPAPI char *mogilefs_sock_read(MogilefsSock *mogilefs_sock, int *buf_len TSRMLS_DC) { /* {{{ */
	char inbuf[MOGILEFS_SOCK_BUF_SIZE], *outbuf, *p, *s, *status, *message, *message_clean;

	s = php_stream_gets(mogilefs_sock->stream, inbuf, 4); /* OK / ERR */
	status = estrndup(s, 2);
	outbuf = php_stream_gets(mogilefs_sock->stream, inbuf, MOGILEFS_SOCK_BUF_SIZE);
	if ((p = strchr(outbuf, '\r'))) {
		*p = '\0';
	}

	if (strcmp(status, "OK") != 0) {
		*buf_len = 0;

		message = php_trim(outbuf, strlen(outbuf), NULL, 0, NULL, 3 TSRMLS_CC);

#ifdef MOGILEFS_DEBUG
		php_printf("ERROR: %s\n", message);
#endif

		message_clean = estrdup(message);
		if ((p = strchr(message_clean, ' '))) {
			strcpy(message_clean, p+1);
		}
		php_url_decode(message_clean, strlen(message_clean));

		zend_throw_exception(mogilefs_exception_class_entry_ptr, message_clean, 0 TSRMLS_CC);

		efree(message);
		efree(message_clean);
		efree(status);
		return NULL;
	}
	*buf_len = strlen(outbuf);
	efree(status);

#ifdef MOGILEFS_DEBUG
	php_printf("RESPONSE: %s\n", outbuf);
#endif

	return outbuf;
}
/* }}} */

PHPAPI char *mogilefs_file_to_mem(char *filename, int *file_buffer_len TSRMLS_DC) /* {{{ */
{
	php_stream *stream;
	char *data = NULL;

	if ((stream = php_stream_open_wrapper(filename, "rb", USE_PATH | ENFORCE_SAFE_MODE, NULL)) != NULL) {
		*file_buffer_len = php_stream_copy_to_mem(stream, &data, PHP_STREAM_COPY_ALL, 0);
		if (*file_buffer_len == 0) {
			data = estrdup("");
		}
		php_stream_close(stream);
	}
	return data;
}
/* }}} */

PHPAPI char *mogilefs_create_open(MogilefsSock *mogilefs_sock, const char * const key,	/* {{{ */
						const char * const class, int multi_dest TSRMLS_DC)
{
	int request_len, response_len;
	char *request = NULL, *response, *close_request = NULL;

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

	close_request = emalloc(response_len + 1U);
	memcpy(close_request, response, response_len + 1U);
	return close_request;
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
	return 0;
}
/* }}} */

PHPAPI int mogilefs_get_uri_path(const char * const url, php_url **p_url TSRMLS_DC) { /* {{{ */
	char *l_key_val, *last, *token, *splitted_key, *splitted_uri, *splitted;
	int splitted_uri_len = 0;
	signed int ret = -2;
	token = estrdup(url);

	for ((l_key_val = strtok_r(token, "&", &last)); l_key_val; (l_key_val = strtok_r(NULL, "&", &last))) {
		if ((splitted_key = estrdup(l_key_val)) == NULL) {
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

/* {{{ proto bool MogileFs::connect(string host, string port, string domain [, int timeout])
	Initialize a new MogileFs Session */
PHP_METHOD(MogileFs, connect)
{
	int host_len, domain_len, id;
	char *host = NULL, *domain = NULL;
	long port;
	struct timeval timeout = { 5L, 0L };
	MogilefsSock *mogilefs_sock = NULL;
	zval *object;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(),
		"Osls|l", &object, mogilefs_class_entry_ptr, &host, &host_len, &port,
		&domain, &domain_len, &timeout.tv_sec) == FAILURE) {

		return;
	}


	if (timeout.tv_sec < 0L || timeout.tv_sec > INT_MAX) {
		zend_throw_exception(mogilefs_exception_class_entry_ptr, "Invalid timeout", 0 TSRMLS_CC);
		RETURN_FALSE;
	}

	mogilefs_sock = mogilefs_sock_server_init(host, host_len, port, domain, domain_len, timeout.tv_sec);
	if (mogilefs_sock_server_open(mogilefs_sock, 1 TSRMLS_CC) < 0) {
		mogilefs_free_socket(mogilefs_sock);
		zend_throw_exception_ex(
			mogilefs_exception_class_entry_ptr,
			0 TSRMLS_CC,
			"Can't connect to %s:%d",
			host,
			port
		);
		RETURN_FALSE;
	}

	id = zend_list_insert(mogilefs_sock, le_mogilefs_sock);
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
		&object, mogilefs_class_entry_ptr) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
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
	int multi_dest = 1, use_file = 1, key_len, class_len, file_buffer_len, filename_len, ret, alloc_file = 0, alloc_url = 0;
	char *key = NULL, *class = NULL, *file_buffer, *filename, *close_request;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(),
				"Osss|bl", &object, mogilefs_class_entry_ptr,
				&filename, &filename_len, &key, &key_len,
				&class, &class_len, &use_file, &multi_dest) == FAILURE) {

			return;
	}

	multi_dest = 0;

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}

	if (use_file) {
		if ((file_buffer = mogilefs_file_to_mem(filename, &file_buffer_len TSRMLS_CC)) == NULL) {
			RETURN_FALSE;
		}
		alloc_file = 1;
	} else {
		file_buffer = filename;
		file_buffer_len = filename_len;
	}

	if ((close_request = mogilefs_create_open(mogilefs_sock, key, class, multi_dest TSRMLS_CC)) == NULL) {
		RETVAL_FALSE;
		goto end;
	}

	if (mogilefs_get_uri_path(close_request, &url TSRMLS_CC) < 0) {
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
		RETVAL_FALSE;
		goto end;
	}

	ne_set_read_timeout(sess, (int) MOGILEFS_DAV_SESSION_TIMEOUT);
	req = ne_request_create(sess, "PUT", url->path);
	ne_set_request_body_buffer(req, file_buffer, file_buffer_len);
	ret = ne_request_dispatch(req);

	ne_request_destroy(req);
	ne_session_destroy(sess);

	if (ret != NE_OK) {
		zend_throw_exception_ex(mogilefs_exception_class_entry_ptr, 0 TSRMLS_CC, "%s", ne_get_error(sess));
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
	if (alloc_file) {
		efree(file_buffer);
	}
	if (alloc_url) {
		php_url_free(url);
	}
}
/* }}} */

/* {{{ proto string mogilefs_get(string key)
	Get MogileFs path */
PHP_METHOD(MogileFs, get)
{
	zval *object;
	MogilefsSock *mogilefs_sock;
	char *key = NULL, *request, *response;
	int key_len, request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Os",
									&object, mogilefs_class_entry_ptr,
									&key, &key_len) == FAILURE) {
			return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}
	request_len = spprintf(&request, 0, "GET_PATHS domain=%s&key=%s\r\n", mogilefs_sock->domain, key);
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
		&object, mogilefs_class_entry_ptr, &key, &key_len) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}

	request_len = spprintf(&request, 0, "DELETE domain=%s&key=%s\r\n", mogilefs_sock->domain, key);
	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}
	RETURN_TRUE;
}

/* }}} */

/* {{{ proto string mogilefs_rename(string src, string dest)
	Move a MogileFs file */
PHP_METHOD(MogileFs, rename)
{
	zval *object;
	MogilefsSock *mogilefs_sock;
	char *src_key = NULL, *dest_key = NULL, *request, *response;
	int src_key_len, dest_key_len, request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Oss",
			&object, mogilefs_class_entry_ptr, &src_key, &src_key_len,
			&dest_key, &dest_key_len) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}
	request_len = spprintf(&request, 0, "RENAME domain=%s&from_key=%s&to_key=%s\r\n", mogilefs_sock->domain, src_key, dest_key);
	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}
	RETURN_TRUE;
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
			&object, mogilefs_class_entry_ptr) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
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
		&object, mogilefs_class_entry_ptr, &prefix, &prefix_len,
		&after, &after_len, &limit) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
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
									mogilefs_class_entry_ptr, &from, &from_len, &to, &to_len) == FAILURE) {
			RETURN_FALSE;
		}

	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|ss",
															&from, &from_len, &to, &to_len) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
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
									mogilefs_class_entry_ptr) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
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
									mogilefs_class_entry_ptr) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
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
		mogilefs_class_entry_ptr, &duration) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}

	request_len = spprintf(&request, 0, "SLEEP domain=%s&duration=%d\r\n", mogilefs_sock->domain, (int) duration);

	if (MOGILEFS_SOCK_WRITE_FREE(mogilefs_sock, request, request_len) < 0) {
		RETURN_FALSE;
	}

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	RETVAL_TRUE;
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
									mogilefs_class_entry_ptr, &all, &all_len) == FAILURE) {
			RETURN_FALSE;
		}

	}else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|s",
															&all, &all_len) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
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
									mogilefs_class_entry_ptr) == FAILURE) {
			RETURN_FALSE;
		}

	}
	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
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
									mogilefs_class_entry_ptr, &devid, &devid_len, &status, &status_len ) == FAILURE) {
			RETURN_FALSE;
		}
	}else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
																												&devid, &devid_len, &status, &status_len) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
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
		&object, mogilefs_class_entry_ptr, &domain, &domain_len) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
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
		&object, mogilefs_class_entry_ptr, &domain, &domain_len) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
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
		&object, mogilefs_class_entry_ptr, &domain, &domain_len,
		&class, &class_len, &mindevcount) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
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
		&object, mogilefs_class_entry_ptr, &domain, &domain_len,
		&class, &class_len, &mindevcount) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
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
		&object, mogilefs_class_entry_ptr, &domain, &domain_len,
		&class, &class_len) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
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
									mogilefs_class_entry_ptr, &host, &host_len, &ip, &ip_len, &port, &port_len) == FAILURE) {
			RETURN_FALSE;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
									&host, &host_len, &ip, &ip_len, &port, &port_len) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
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
				mogilefs_class_entry_ptr, &host, &host_len, &ip, &ip_len, &port, &port_len, &status, &status_len) == FAILURE) {
			RETURN_FALSE;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss|s",
									&host, &host_len, &ip, &ip_len, &port, &port_len, &status, &status_len) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (!strcmp("alive", status) && !strcmp("dead", status)) {
		zend_throw_exception(mogilefs_exception_class_entry_ptr, "Invalid connection status", 0 TSRMLS_CC);
		RETURN_FALSE;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
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
									mogilefs_class_entry_ptr, &host, &host_len) == FAILURE) {
			RETURN_FALSE;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
									&host, &host_len) == FAILURE) {
			RETURN_FALSE;
		}
	}


	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
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
						mogilefs_class_entry_ptr, &host, &host_len, &device, &device_len, &weight, &weight_len) == FAILURE) {
			RETURN_FALSE;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
												&host, &host_len, &device, &device_len, &weight, &weight_len) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
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
						mogilefs_class_entry_ptr, &host, &host_len, &device, &device_len, &state, &state_len) == FAILURE) {
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
									mogilefs_class_entry_ptr, &disable, &disable_len, &level, &level_len) == FAILURE) {
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
		&object, mogilefs_class_entry_ptr) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(object, &mogilefs_sock TSRMLS_CC) < 0) {
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
		&object, mogilefs_class_entry_ptr) == FAILURE) {

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

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
