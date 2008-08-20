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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "ext/standard/url.h"
#include "zend_extensions.h"
#include "zend_interfaces.h"
#include "zend_exceptions.h"

#include "php_mogilefs.h"
#include <ne_socket.h>
#include <ne_session.h>
#include <ne_utils.h>
#include <ne_auth.h>
#include <ne_basic.h>

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>

ZEND_DECLARE_MODULE_GLOBALS(mogilefs)

/* True global resources - no need for thread safety here */
static int le_mogilefs_sock;
#define mogilefs_sock_name "MogileFS Socket Buffer"
static zend_class_entry *mogilefs_class_entry_ptr;
static zend_class_entry *mogilefs_exception_class_entry_ptr;

/* {{{ mogilefs_functions[]
 *
 * Every user visible function must have an entry in mogilefs_functions[].
 */
zend_function_entry mogilefs_functions[] = {
	PHP_FE(mogilefs_connect, NULL)
	PHP_FE(mogilefs_get, NULL)
	PHP_FE(mogilefs_get_domains, NULL)
	PHP_FE(mogilefs_list_keys, NULL)
	PHP_FE(mogilefs_list_fids, NULL)
	PHP_FE(mogilefs_get_hosts, NULL)
	PHP_FE(mogilefs_get_devices, NULL)
	PHP_FE(mogilefs_sleep, NULL)
	PHP_FE(mogilefs_stats, NULL)
	PHP_FE(mogilefs_replicate, NULL)
	PHP_FE(mogilefs_create_device, NULL)
	PHP_FE(mogilefs_create_domain, NULL)
	PHP_FE(mogilefs_delete_domain, NULL)
	PHP_FE(mogilefs_create_class, NULL)
	PHP_FE(mogilefs_update_class, NULL)
	PHP_FE(mogilefs_delete_class, NULL)
	PHP_FE(mogilefs_create_host, NULL)
	PHP_FE(mogilefs_update_host, NULL)
	PHP_FE(mogilefs_delete_host, NULL)
	PHP_FE(mogilefs_set_weight, NULL)
	PHP_FE(mogilefs_set_state, NULL)
	PHP_FE(mogilefs_checker, NULL)
	PHP_FE(mogilefs_monitor_round, NULL)
	PHP_FALIAS(mogilefs_get_paths, mogilefs_get, NULL)
	PHP_FE(mogilefs_put, NULL)
	PHP_FE(mogilefs_close, NULL)
	PHP_FE(mogilefs_delete, NULL)
	PHP_FE(mogilefs_rename, NULL)
	{NULL, NULL, NULL}	/* Must be the last line in mogilefs_functions[] */
};

static zend_function_entry php_mogilefs_class_functions[] = {
	PHP_FALIAS(connect, mogilefs_connect, NULL)
	PHP_FALIAS(get, mogilefs_get, NULL)
	PHP_FALIAS(getPaths, mogilefs_get, NULL)
	PHP_FALIAS(getDomains, mogilefs_get_domains, NULL)
	PHP_FALIAS(listKeys, mogilefs_list_keys, NULL)
	PHP_FALIAS(listFids, mogilefs_list_fids, NULL)
	PHP_FALIAS(getHosts, mogilefs_get_hosts, NULL)
	PHP_FALIAS(getDevices, mogilefs_get_devices, NULL)
	PHP_FALIAS(sleep, mogilefs_sleep, NULL)
	PHP_FALIAS(stats, mogilefs_stats, NULL)
	PHP_FALIAS(replicate, mogilefs_replicate, NULL)
	PHP_FALIAS(createDevice, mogilefs_create_device, NULL)
	PHP_FALIAS(createDomain, mogilefs_create_domain, NULL)
	PHP_FALIAS(deleteDomain, mogilefs_delete_domain, NULL)
	PHP_FALIAS(createClass, mogilefs_create_class, NULL)
	PHP_FALIAS(updateClass, mogilefs_update_class, NULL)
	PHP_FALIAS(deleteClass, mogilefs_delete_class, NULL)
	PHP_FALIAS(createHost, mogilefs_create_host, NULL)
	PHP_FALIAS(updateHost, mogilefs_update_host, NULL)
	PHP_FALIAS(deleteHost, mogilefs_delete_host, NULL)
	PHP_FALIAS(setWeight, mogilefs_set_weight, NULL)
	PHP_FALIAS(setState, mogilefs_set_state, NULL)
	PHP_FALIAS(checker, mogilefs_checker, NULL)
	PHP_FALIAS(monitorRound, mogilefs_monitor_round, NULL)
	PHP_FALIAS(put, mogilefs_put, NULL)
	PHP_FALIAS(close, mogilefs_close, NULL)
	PHP_FALIAS(delete, mogilefs_delete, NULL)
	PHP_FALIAS(rename, mogilefs_rename, NULL)
	{NULL, NULL, NULL}
};
/* }}} */

/* {{{ mogilefs_module_entry
 */

static zend_module_dep mogilefs_module_deps[] = {
	{NULL, NULL, NULL, 0}
};


zend_module_entry mogilefs_module_entry = {
#if ZEND_EXTENSION_API_NO >= 220050617
	STANDARD_MODULE_HEADER_EX, NULL,
	mogilefs_module_deps,
#else
	STANDARD_MODULE_HEADER,
#endif
	"mogilefs",
	mogilefs_functions,
	PHP_MINIT(mogilefs),
	PHP_MSHUTDOWN(mogilefs),
	PHP_RINIT(mogilefs),
	PHP_RSHUTDOWN(mogilefs),
	PHP_MINFO(mogilefs),
#if ZEND_MODULE_API_NO >= 20010901
	PHP_MOGILEFS_VERSION,
#endif
	PHP_MODULE_GLOBALS(mogilefs),
	NULL,
	NULL,
	NULL,
	STANDARD_MODULE_PROPERTIES_EX
};
/* }}} */

#ifdef COMPILE_DL_MOGILEFS
ZEND_GET_MODULE(mogilefs)
#endif

/* {{{ internal function protos */
int mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAMETERS, const char * const, int);
MogilefsSock* mogilefs_sock_server_init(char *, int, unsigned short, char *, int, long);
int mogilefs_sock_disconnect(MogilefsSock * TSRMLS_DC);
int mogilefs_sock_connect(MogilefsSock * TSRMLS_DC);
int mogilefs_sock_server_open(MogilefsSock *, int TSRMLS_DC);
int mogilefs_sock_get(zval *, MogilefsSock ** TSRMLS_DC);
int mogilefs_sock_write(MogilefsSock *, const char *, int TSRMLS_DC);
char * mogilefs_sock_read(MogilefsSock *, int * TSRMLS_DC);
char * mogilefs_file_to_mem(char *, int * TSRMLS_DC);
char * mogilefs_create_open(MogilefsSock *, const char * const, const char * const, int TSRMLS_DC);
int mogilefs_create_close(MogilefsSock *, const char * const, const char * const, const char * const TSRMLS_DC);
int mogilefs_get_uri_path(const char * const, php_url ** TSRMLS_DC);
void mogilefs_free_socket(MogilefsSock *socket);
/* }}} */

/* {{{ mogilefs default_link */

static void mogilefs_set_default_link(int id TSRMLS_DC)
{
	if (MOGILEFS_G(default_link) != -1) {
		zend_list_delete(MOGILEFS_G(default_link));
	}
	MOGILEFS_G(default_link) = id;
	zend_list_addref(id);
}

static int mogilefs_get_default_link(INTERNAL_FUNCTION_PARAMETERS)
{
	return MOGILEFS_G(default_link);
}
/* }}} */

/* {{{ static void mogilefs_destructor_mogilefs_sock(zend_rsrc_list_entry * rsrc *TSRMLS_DC)
 */
static void mogilefs_destructor_mogilefs_sock(zend_rsrc_list_entry * rsrc TSRMLS_DC)
{
	MogilefsSock *mogilefs_sock = (MogilefsSock *) rsrc->ptr;
	mogilefs_sock_disconnect(mogilefs_sock TSRMLS_CC);
	mogilefs_free_socket(mogilefs_sock);
}
/* }}} */

/* {{{ mogilefs_free_socket(MogilefsSock *socket)
 */
void mogilefs_free_socket(MogilefsSock *mogilefs_sock)
{
	efree(mogilefs_sock->host);
	efree(mogilefs_sock->domain);
	efree(mogilefs_sock);
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(mogilefs)
{
	ne_sock_init();
	zend_class_entry mogilefs_class_entry;
	INIT_CLASS_ENTRY(mogilefs_class_entry, "MogileFs", php_mogilefs_class_functions);
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

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(mogilefs)
{
	ne_sock_exit();
	UNREGISTER_INI_ENTRIES();
	return SUCCESS;
}
/** }}} */

/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(mogilefs)
{
	MOGILEFS_G(default_link) = -1;
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(mogilefs)
{
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(mogilefs)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "mogilefs support", "enabled");
	php_info_print_table_row(2, "Version", PHP_MOGILEFS_VERSION);
	php_info_print_table_row(2, "Revision", "$Id$");
	php_info_print_table_end();
}
/* }}} */

int mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAMETERS, const char * const result, int result_len) { /* {{{ */
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

MogilefsSock *mogilefs_sock_server_init(char *m_host, int m_host_len, unsigned short m_port, /* {{{ */
										char *m_domain, int m_domain_len, long timeout) {
	MogilefsSock *mogilefs_sock;

	mogilefs_sock = emalloc(sizeof *mogilefs_sock);
	mogilefs_sock->host = emalloc(m_host_len + 1);
	mogilefs_sock->domain = emalloc(m_domain_len + 1);
	mogilefs_sock->stream = NULL;
	mogilefs_sock->status = MOGILEFS_SOCK_STATUS_DISCONNECTED;

	memcpy(mogilefs_sock->host, m_host, m_host_len);
	memcpy(mogilefs_sock->domain, m_domain, m_domain_len);
	mogilefs_sock->host[m_host_len] = '\0';
	mogilefs_sock->domain[m_domain_len] = '\0';

	mogilefs_sock->port = m_port;
	mogilefs_sock->timeout = timeout;

	return mogilefs_sock;
}
/* }}} */

int mogilefs_sock_disconnect(MogilefsSock *mogilefs_sock TSRMLS_DC) { /* {{{ */
	if (mogilefs_sock->stream != NULL) {
		mogilefs_sock_write(mogilefs_sock, "quit", 4 TSRMLS_CC);
		mogilefs_sock->status = MOGILEFS_SOCK_STATUS_DISCONNECTED;
		php_stream_close(mogilefs_sock->stream);
		mogilefs_sock->stream = NULL;
		return 1;
	}
	return 0;
}
/* }}} */

int mogilefs_sock_connect(MogilefsSock *mogilefs_sock TSRMLS_DC) { /* {{{ */
	struct timeval tv;
	char *m_host = NULL, *hash_key = NULL, *errstr = NULL;
	int	m_host_len, err = 0;

	if (mogilefs_sock->stream != NULL) {
		mogilefs_sock_disconnect(mogilefs_sock TSRMLS_CC);
	}

	tv.tv_sec = mogilefs_sock->timeout;
	tv.tv_usec = 0;

	m_host_len = spprintf(&m_host, 0, "%s:%d", mogilefs_sock->host, mogilefs_sock->port);

	mogilefs_sock->stream = php_stream_xport_create(
		m_host,
		m_host_len,
		ENFORCE_SAFE_MODE,
		STREAM_XPORT_CLIENT | STREAM_XPORT_CONNECT,
		hash_key,
		&tv,
		NULL,
		&errstr,
		&err
	);

	if (!mogilefs_sock->stream) {
		efree(m_host);
		efree(errstr);
		return -1;
	}
	efree(m_host);

	php_stream_auto_cleanup(mogilefs_sock->stream);
	php_stream_set_option(mogilefs_sock->stream, PHP_STREAM_OPTION_READ_TIMEOUT, 0, &tv);
	php_stream_set_option(mogilefs_sock->stream, PHP_STREAM_OPTION_WRITE_BUFFER, PHP_STREAM_BUFFER_NONE, NULL);
	mogilefs_sock->status = MOGILEFS_SOCK_STATUS_CONNECTED;
	return 0;
}
/* }}} */

int mogilefs_sock_server_open(MogilefsSock *mogilefs_sock, int force_connect TSRMLS_DC) { /* {{{ */
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

int mogilefs_sock_get(zval *id, MogilefsSock **mogilefs_sock TSRMLS_DC) { /* {{{ */
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

int mogilefs_sock_write(MogilefsSock *mogilefs_sock, const char *cmd, int cmd_len TSRMLS_DC) { /* {{{ */
	if (php_stream_write(mogilefs_sock->stream, cmd, cmd_len) != cmd_len) {
		return -1;
	}
	return 0;
}
/* }}} */

char *mogilefs_sock_read(MogilefsSock *mogilefs_sock, int *buf_len TSRMLS_DC) { /* {{{ */
	char inbuf[MOGILEFS_SOCK_BUF_SIZE], *outbuf, *p, *s, *status, *message, *message_clean;

	s = php_stream_gets(mogilefs_sock->stream, inbuf, 4); /* OK / ERR */
	status = estrndup(s, 2);
	outbuf = php_stream_gets(mogilefs_sock->stream, inbuf, MOGILEFS_SOCK_BUF_SIZE);
	if ((p = strchr(outbuf, '\r'))) {
		*p = '\0';
	}

	if (strcmp(status, "OK") != 0) {
		*buf_len = 0;

		message = php_trim(outbuf, strlen(outbuf), NULL, NULL, NULL, 3);
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

	return outbuf;
}
/* }}} */

char *mogilefs_file_to_mem(char *m_file, int *m_file_len TSRMLS_DC) /* {{{ */
{
	php_stream *stream;
	char *data = NULL;

	if ((stream = php_stream_open_wrapper(m_file, "rb", USE_PATH | ENFORCE_SAFE_MODE, NULL)) != NULL) {
		*m_file_len = php_stream_copy_to_mem(stream, &data, PHP_STREAM_COPY_ALL, 0);
		if (*m_file_len == 0) {
			data = estrdup("");
		}
		php_stream_close(stream);
	}
	return data;
}
/* }}} */

char *mogilefs_create_open(MogilefsSock *mogilefs_sock, const char * const m_key,	/* {{{ */
						const char * const m_class, int multi_dest TSRMLS_DC)
{
	int request_len, response_len;
	char *request = NULL, *response, *close_request = NULL;

	request_len = spprintf(&request, 0, "CREATE_OPEN domain=%s&key=%s&class=%s&multi_dest=%d\r\n",
							mogilefs_sock->domain, m_key, m_class, multi_dest);

	if (mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		return NULL;
	}
	efree(request);

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		return NULL;
	}

	close_request = emalloc(response_len + 1U);
	memcpy(close_request, response, response_len + 1U);
	return close_request;
}
/* }}} */

int mogilefs_create_close(MogilefsSock *mogilefs_sock, const char * const m_key, /* {{{ */
						 const char * const m_class, const char * const close_request TSRMLS_DC)
{
	int request_len, response_len;
	char *request = NULL, *response;

	request_len = spprintf(&request, 0, "CREATE_CLOSE domain=%s&key=%s&class=%s&%s\r\n",
							mogilefs_sock->domain, m_key, m_class, close_request);
	if (mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		return -1;
	}
	efree(request);

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		return -1;
	}
	return 0;
}
/* }}} */

int mogilefs_get_uri_path(const char * const url, php_url **p_url TSRMLS_DC) { /* {{{ */
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

/* {{{ proto string mogilefs_connect(string host, string port, string domain [, int timeout])
	Initialize a new MogileFS Session */

PHP_FUNCTION(mogilefs_connect)
{
	char *m_host = NULL, *m_domain = NULL;
	int m_host_len, m_domain_len, id;
	long m_port;
	struct timeval timeout = { 5L, 0L };
	MogilefsSock *mogilefs_sock = NULL;
	zval *mg_object = getThis();

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sls|l",
							 &m_host, &m_host_len, &m_port,
							 &m_domain, &m_domain_len, &timeout.tv_sec) == FAILURE) {
		RETURN_FALSE;
	}


	if (timeout.tv_sec < 0L || timeout.tv_sec > INT_MAX) {
		zend_throw_exception(mogilefs_exception_class_entry_ptr, "Invalid timeout", 0 TSRMLS_CC);
		RETURN_FALSE;
	}

	mogilefs_sock = mogilefs_sock_server_init(m_host, m_host_len, m_port, m_domain, m_domain_len, timeout.tv_sec);
	if (mogilefs_sock_server_open(mogilefs_sock, 1 TSRMLS_CC) < 0) {
		mogilefs_free_socket(mogilefs_sock);
		zend_throw_exception_ex(
			mogilefs_exception_class_entry_ptr,
			0 TSRMLS_CC,
			"Can't connect to %s:%d",
			m_host,
			m_port
		);
		RETURN_FALSE;
	}


	if (!mg_object) {
		object_init_ex(return_value, mogilefs_class_entry_ptr);
		id = zend_list_insert(mogilefs_sock, le_mogilefs_sock);
		add_property_resource(return_value, "socket", id);
	} else {
		id = zend_list_insert(mogilefs_sock, le_mogilefs_sock);
		add_property_resource(mg_object, "socket", id);
		RETURN_TRUE;
	}
}

/* }}} */

/* {{{ proto string mogilefs_close()
	Close a MogileFS Session */

PHP_FUNCTION(mogilefs_close)
{
	zval *mg_object;
	MogilefsSock *mogilefs_sock = NULL;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "O",
		&mg_object, mogilefs_class_entry_ptr) == FAILURE) {

		RETURN_FALSE;
	}

	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}

	if (mogilefs_sock_disconnect(mogilefs_sock TSRMLS_CC)) {
		RETURN_TRUE;
	}
	RETURN_FALSE;
}

/* }}} */

/* {{{ proto string mogilefs_put([MogileFS Object,] string file, string key, string class [, bool use_file_only [, bool multi_dest]])
	Get MogileFS path */

PHP_FUNCTION(mogilefs_put)
{
	zval *mg_object;
	MogilefsSock *mogilefs_sock;
	php_url *url;
	ne_session *sess;
	ne_request *req;
	int multi_dest = 1, use_file_only = 1, m_key_len, m_class_len, m_buf_file_len;
	int m_file_len, ret, alloc_internal = 0, alloc_url = 0;
	char *m_key = NULL, *m_class = NULL, *m_buf_file, *m_file, *close_request;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(),
				"Osss|ll", &mg_object, mogilefs_class_entry_ptr,
				&m_file, &m_file_len, &m_key, &m_key_len,
				&m_class, &m_class_len, &use_file_only, &multi_dest) == FAILURE) {
			RETURN_FALSE;
	}

	if (use_file_only != 0 && use_file_only != 1) {
		use_file_only = 1;
	}

	multi_dest = 0;

	if ((m_buf_file = mogilefs_file_to_mem(m_file, &m_buf_file_len TSRMLS_CC)) == NULL) {
		if (use_file_only == 0) {
			m_buf_file = m_file;
			m_buf_file_len = m_file_len;
		} else if (use_file_only == 1) {
			RETURN_FALSE;
		}
	} else {
		alloc_internal = 1;
	}

	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETVAL_FALSE;
	}

	if ((close_request = mogilefs_create_open(mogilefs_sock, m_key, m_class, multi_dest TSRMLS_CC)) == NULL) {
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
	ne_set_request_body_buffer(req, m_buf_file, m_buf_file_len);
	ret = ne_request_dispatch(req);

	ne_request_destroy(req);
	ne_session_destroy(sess);

	if (ret != NE_OK) {
		zend_throw_exception_ex(mogilefs_exception_class_entry_ptr, 0 TSRMLS_CC, "%s", ne_get_error(sess));
		RETVAL_FALSE;
		goto end;
	}

	if (mogilefs_create_close(mogilefs_sock, m_key, m_class, close_request TSRMLS_CC) < 0) {
				RETVAL_FALSE;
		goto end;
	}

	RETVAL_TRUE;

end:
	if (close_request) {
		efree(close_request);
	}
	if (alloc_internal) {
		efree(m_buf_file);
	}
	if (alloc_url) {
		php_url_free(url);
	}
}
/* }}} */

/* {{{ proto string mogilefs_get([MogileFS Object,] string key)
	Get MogileFS path */

PHP_FUNCTION(mogilefs_get)
{
	zval *mg_object;
	MogilefsSock *mogilefs_sock;
	char *m_key = NULL, *request, *response;
	int m_key_len, request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Os",
									&mg_object, mogilefs_class_entry_ptr,
									&m_key, &m_key_len) == FAILURE) {
			RETURN_FALSE;
	}

	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}
	request_len = spprintf(&request, 0, "GET_PATHS domain=%s&key=%s\r\n", mogilefs_sock->domain, m_key);
	if (mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		RETURN_FALSE;
	}
	efree(request);

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}
	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
}

/* }}} */

/* {{{ proto string mogilefs_delete([MogileFS Object,] string key)
	Delete a MogileFS file */
PHP_FUNCTION(mogilefs_delete)
{
	zval *mg_object;
	MogilefsSock *mogilefs_sock;
	char *m_key = NULL, *request, *response;
	int m_key_len, request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Os",
		&mg_object, mogilefs_class_entry_ptr, &m_key, &m_key_len) == FAILURE) {

		RETURN_FALSE;
	}

	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}

	request_len = spprintf(&request, 0, "DELETE domain=%s&key=%s\r\n", mogilefs_sock->domain, m_key);
	if (mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		RETURN_FALSE;
	}
	efree(request);

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}
	RETURN_TRUE;
}

/* }}} */

/* {{{ proto string mogilefs_rename([MogileFS Object,] string src_key, string_dest_key)
	Move a MogileFS file */

PHP_FUNCTION(mogilefs_rename)
{
	zval *mg_object;
	MogilefsSock *mogilefs_sock;
	char *m_src_key = NULL, *m_dest_key = NULL, *request, *response;
	int m_src_key_len, m_dest_key_len, request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Oss",
			&mg_object, mogilefs_class_entry_ptr, &m_src_key, &m_src_key_len,
			&m_dest_key, &m_dest_key_len) == FAILURE) {

		RETURN_FALSE;
	}

	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}
	request_len = spprintf(&request, 0, "RENAME domain=%s&from_key=%s&to_key=%s\r\n", mogilefs_sock->domain, m_src_key, m_dest_key);
	if (mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		RETURN_FALSE;
	}
	efree(request);

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}
	RETURN_TRUE;
}

/* }}} */

/* {{{ proto string mogilefs_get_domains([MogileFS Object,])
	Get MogileFS domains */

PHP_FUNCTION(mogilefs_get_domains)
{
	zval *mg_object;
	MogilefsSock *mogilefs_sock;
	char *request, *response;
	int	request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "O",
			&mg_object, mogilefs_class_entry_ptr) == FAILURE) {

		RETURN_FALSE;
	}

	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}
	request_len = spprintf(&request, 0, "GET_DOMAINS\r\n", mogilefs_sock->domain);
	if (mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		RETURN_FALSE;
	}
	efree(request);

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}
	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
}

/* }}} */

/* {{{ proto string mogilefs_list_keys([MogileFS Object,])
	Get MogileFS file keys */

PHP_FUNCTION(mogilefs_list_keys)
{
	zval *mg_object;
	MogilefsSock *mogilefs_sock;
	char *m_prefix = NULL, *m_after = NULL, *request, *response;
	long m_limit = 1000;
	int m_prefix_len, m_after_len, m_limit_len, request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Oss|l",
		&mg_object, mogilefs_class_entry_ptr, &m_prefix, &m_prefix_len,
		&m_after, &m_after_len, &m_limit) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}


	request_len = spprintf(
		&request,
		0,
		"LIST_KEYS domain=%s&prefix=%s&after=%s&limit=%d\r\n",
		mogilefs_sock->domain,
		m_prefix,
		m_after,
		m_limit
	);

	if (mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		RETURN_FALSE;
	}
	efree(request);

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}
	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ proto string mogilefs_list_fids([MogileFS Object,])
	Get MogileFS file ids */
PHP_FUNCTION(mogilefs_list_fids)
{
	zval *mg_object = getThis();
	MogilefsSock *mogilefs_sock;
	char *m_to = "100", *m_from = "0", *request, *response;
	int	m_to_len, m_from_len, request_len, response_len;

	if (mg_object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O|ss", &mg_object,
									mogilefs_class_entry_ptr, &m_from, &m_from_len, &m_to, &m_to_len) == FAILURE) {
			RETURN_FALSE;
		}

	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|ss",
															&m_from, &m_from_len, &m_to, &m_to_len) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}

	request_len = spprintf(&request, 0, "LIST_FIDS domain=%s&from=%s&to=%s\r\n", mogilefs_sock->domain, m_from, m_to);

	if (mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		RETURN_FALSE;
	}
	efree(request);

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}
	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
}


/* }}} */

/* {{{ proto string mogilefs_get_hosts([MogileFS Object,])
	Get MogileFS hosts */
PHP_FUNCTION(mogilefs_get_hosts)
{
	zval *mg_object = getThis();
	MogilefsSock *mogilefs_sock;
	char *request, *response;
	int request_len, response_len;

	if (mg_object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &mg_object,
									mogilefs_class_entry_ptr) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}

	request_len = spprintf(&request, 0, "GET_HOSTS domain=%s\r\n", mogilefs_sock->domain);

	if (mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		RETURN_FALSE;
	}
	efree(request);

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
}


/* }}} */

/* {{{ proto string mogilefs_get_devices([MogileFS Object,])
	Get MogileFS devices */
PHP_FUNCTION(mogilefs_get_devices)
{
	zval *mg_object = getThis();
	MogilefsSock *mogilefs_sock;
	char *request, *response;
	int request_len, response_len;

	if(mg_object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &mg_object,
									mogilefs_class_entry_ptr) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}

	request_len = spprintf(&request, 0, "GET_DEVICES domain=%s\r\n", mogilefs_sock->domain);

	if(mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		RETURN_FALSE;
	}
	efree(request);

	if((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if(mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}

}

/* }}} */

/* {{{ proto string mogilefs_sleep([MogileFS Object, ingeter duration])
	*/
PHP_FUNCTION(mogilefs_sleep)
{
	zval *mg_object;
	MogilefsSock *mogilefs_sock;
	char *request, *response;
	long duration;
	int	request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "O|l", &mg_object,
		mogilefs_class_entry_ptr, &duration) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}

	request_len = spprintf(&request, 0, "SLEEP domain=%s&duration=%d\r\n", mogilefs_sock->domain, duration);

	if (mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		RETURN_FALSE;
	}
	efree(request);

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	RETVAL_TRUE;
}

/* }}} */

/* {{{ proto string mogilefs_stats([MogileFS Object], string all)
	*/
PHP_FUNCTION(mogilefs_stats)
{
	zval *mg_object = getThis();
	MogilefsSock *mogilefs_sock;
	char *m_all = "1", *request, *response;
	int	m_all_len, request_len, response_len;

	if(mg_object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O|s", &mg_object,
									mogilefs_class_entry_ptr, &m_all, &m_all_len) == FAILURE) {
			RETURN_FALSE;
		}

	}else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|s",
															&m_all, &m_all_len) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}

	request_len = spprintf(&request, 0, "STATS domain=%s&all=%s\r\n", mogilefs_sock->domain, m_all);

	if(mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		RETURN_FALSE;
	}
	efree(request);

	if((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}
	if(mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}

}

/* }}} */

/* {{{ proto string mogilefs_replicate([MogileFS Object])
	*/
PHP_FUNCTION(mogilefs_replicate)
{
	zval *mg_object = getThis();
	MogilefsSock *mogilefs_sock;
	char	*request, *response;
	int	 request_len, response_len;

	if(mg_object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &mg_object,
									mogilefs_class_entry_ptr) == FAILURE) {
			RETURN_FALSE;
		}

	}
	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}

	request_len = spprintf(&request, 0, "REPLICATE_NOW domain=%s\r\n", mogilefs_sock->domain);

	if (mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		RETURN_FALSE;
	}
	efree(request);

	if((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if(mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}

}

/* }}} */

/* {{{ proto string mogilefs_create_device([MogileFS Object], string devid, string status)
	*/
PHP_FUNCTION(mogilefs_create_device)
{
	zval *mg_object = getThis();
	MogilefsSock *mogilefs_sock;
	char *status, *devid, *request, *response;
	int	status_len, devid_len, request_len, response_len;

	if(mg_object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Oss", &mg_object,
									mogilefs_class_entry_ptr, &devid, &devid_len, &status, &status_len ) == FAILURE) {
			RETURN_FALSE;
		}
	}else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
																												&devid, &devid_len, &status, &status_len) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}

	request_len = spprintf(&request, 0, "CREATE_DEVICE domain=%s&status=%s&devid=%s\r\n", mogilefs_sock->domain, status, devid);

	if (mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		RETURN_FALSE;
	}
	efree(request);

	if((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if(mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}

}

/* }}} */

/* {{{ proto string mogilefs_create_domain([MogileFS Object], string domain)
	*/
PHP_FUNCTION(mogilefs_create_domain)
{
	zval *mg_object;
	MogilefsSock *mogilefs_sock;
	char *domain, *request, *response;
	int	domain_len, request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Os",
		&mg_object, mogilefs_class_entry_ptr, &domain, &domain_len) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}

	request_len = spprintf(&request, 0, "CREATE_DOMAIN domain=%s\r\n", domain);

	if (mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		RETURN_FALSE;
	}
	efree(request);

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}

}

/* }}} */

/* {{{ proto string mogilefs_delete_domain([MogileFS Object], string domain)
	*/
PHP_FUNCTION(mogilefs_delete_domain)
{
	zval *mg_object;
	MogilefsSock *mogilefs_sock;
	char *domain, *request, *response;
	int	domain_len, request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Os",
		&mg_object, mogilefs_class_entry_ptr, &domain, &domain_len) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}

	request_len = spprintf(&request, 0, "DELETE_DOMAIN domain=%s\r\n", domain);

	if (mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		RETURN_FALSE;
	}
	efree(request);

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}

}

/* }}} */

/* {{{ proto string mogilefs_create_class([MogileFS Object], string domain, string class, string mindevcount)
	*/
PHP_FUNCTION(mogilefs_create_class)
{
	zval *mg_object;
	MogilefsSock *mogilefs_sock;
	char *domain = NULL, *class, *mindevcount = "0", *request, *response;
	int	domain_len, class_len, mindevcount_len, request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Osss",
		&mg_object, mogilefs_class_entry_ptr, &domain, &domain_len,
		&class, &class_len, &mindevcount, &mindevcount_len) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}

	if (domain == NULL || domain == "\0" || strlen(domain) == 0) {
		domain = mogilefs_sock->domain;
	}

	request_len = spprintf(
		&request,
		0,
		"CREATE_CLASS domain=%s&class=%s&mindevcount=%s\r\n",
		domain,
		class,
		mindevcount
	);

	if (mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		RETURN_FALSE;
	}
	efree(request);

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}

}

/* }}} */

/* {{{ proto string mogilefs_update_class([MogileFS Object], string domain, string class, string mindevcount)
	*/
PHP_FUNCTION(mogilefs_update_class)
{
	zval *mg_object;
	MogilefsSock *mogilefs_sock;
	char *domain = NULL, *class, *mindevcount = "0", *request, *response;
	int	domain_len, class_len, mindevcount_len, request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Osss",
		&mg_object, mogilefs_class_entry_ptr, &domain, &domain_len,
		&class, &class_len, &mindevcount, &mindevcount_len) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}

	if (domain == NULL || domain == "\0" || strlen(domain) == 0) {
		domain = mogilefs_sock->domain;
	}

	request_len = spprintf(
		&request,
		0,
		"UPDATE_CLASS domain=%s&class=%s&mindevcount=%s&update=1\r\n",
		domain,
		class,
		mindevcount
	);

	if (mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		RETURN_FALSE;
	}
	efree(request);

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}

}

/* }}} */

/* {{{ proto string mogilefs_delete_class([MogileFS Object], string domain, string class)
	*/
PHP_FUNCTION(mogilefs_delete_class)
{
	zval *mg_object;
	MogilefsSock *mogilefs_sock;
	char *domain = NULL, *class, *request, *response;
	int	domain_len, class_len, request_len, response_len;

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Oss",
		&mg_object, mogilefs_class_entry_ptr, &domain, &domain_len,
		&class, &class_len) == FAILURE) {

		return;
	}

	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}

	if (domain == NULL || domain == "\0" || strlen(domain) == 0) {
		domain = mogilefs_sock->domain;
	}

	request_len = spprintf(&request, 0, "DELETE_CLASS domain=%s&class=%s\r\n", domain, class);

	if (mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		RETURN_FALSE;
	}
	efree(request);

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}

}

/* }}} */

/* {{{ proto string mogilefs_create_host([MogileFS Object], string domain, string class)
	*/
PHP_FUNCTION(mogilefs_create_host)
{
	zval *mg_object = getThis();
	MogilefsSock *mogilefs_sock;
	char *host, *ip, *port, *request, *response;
	int	host_len, ip_len, port_len, request_len, response_len;

	if (mg_object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Osss", &mg_object,
									mogilefs_class_entry_ptr, &host, &host_len, &ip, &ip_len, &port, &port_len) == FAILURE) {
			RETURN_FALSE;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
									&host, &host_len, &ip, &ip_len, &port, &port_len) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}
	request_len = spprintf(&request, 0, "CREATE_HOST domain=%s&host=%s&ip=%s&port=%s\r\n", mogilefs_sock->domain, host, ip, port);
	if (mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		RETURN_FALSE;
	}
	efree(request);

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
}

/* }}} */

/* {{{ proto string mogilefs_update_host([MogileFS Object], string hostname, string ip, string port, string status[dead, alive])
	*/
PHP_FUNCTION(mogilefs_update_host)
{
	zval *mg_object = getThis();
	MogilefsSock *mogilefs_sock;
	char *host, *ip, *port, *status = "alive", *request, *response;
	int	host_len, ip_len, port_len, status_len, request_len, response_len;

	if (mg_object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Osss|s", &mg_object,
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

	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}
	request_len = spprintf(&request, 0, "UPDATE_HOST domain=%s&host=%s&ip=%s&port=%s&status=%s&update=1\r\n", mogilefs_sock->domain, host, ip, port, status);

	if(mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		RETURN_FALSE;
	}
	efree(request);

	if((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
}

/* }}} */

/* {{{ proto string mogilefs_delete_host([MogileFS Object], string host)
	*/
PHP_FUNCTION(mogilefs_delete_host)
{
	zval *mg_object = getThis();
	MogilefsSock *mogilefs_sock;
	char *host,	*request, *response;
	int host_len, request_len, response_len;

	if (mg_object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Os", &mg_object,
									mogilefs_class_entry_ptr, &host, &host_len) == FAILURE) {
			RETURN_FALSE;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
									&host, &host_len) == FAILURE) {
			RETURN_FALSE;
		}
	}


	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}
	request_len = spprintf(&request, 0, "DELETE_HOST domain=%s&host=%s\r\n", mogilefs_sock->domain, host);

	if (mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		RETURN_FALSE;
	}
	efree(request);

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}

	RETURN_TRUE;
}

/* }}} */

/* {{{ proto string mogilefs_set_weight([MogileFS Object], string host)
	*/
PHP_FUNCTION(mogilefs_set_weight)
{
	zval *mg_object = getThis();
	MogilefsSock *mogilefs_sock;
	char *host,	*device, *weight,	*request, *response;
	int	host_len, device_len, weight_len, request_len, response_len;

	if (mg_object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Osss", &mg_object,
						mogilefs_class_entry_ptr, &host, &host_len, &device, &device_len, &weight, &weight_len) == FAILURE) {
			RETURN_FALSE;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
												&host, &host_len, &device, &device_len, &weight, &weight_len) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}
	request_len = spprintf(&request, 0, "SET_WEIGHT domain=%s&host=%s&device=%s&weight=%s\r\n", mogilefs_sock->domain, host, device, weight);

	if (mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		RETURN_FALSE;
	}
	efree(request);

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
	RETURN_TRUE;
}

/* }}} */

/* {{{ proto string mogilefs_set_state([MogileFS Object], string host, string device, string state)
	*/
PHP_FUNCTION(mogilefs_set_state)
{
	zval *mg_object = getThis();
	MogilefsSock *mogilefs_sock;
	char *host,	*device, *state = "alive",	*request, *response;
	int	host_len, device_len, state_len, request_len, response_len;

	if (mg_object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Osss", &mg_object,
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

	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}
	request_len = spprintf(&request, 0, "SET_STATE domain=%s&host=%s&device=%s&state=%s\r\n", mogilefs_sock->domain, host, device, state);

	if (mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		RETURN_FALSE;
	}
	efree(request);

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
	 RETURN_TRUE;
}

/* }}} */

/* {{{ proto string mogilefs_checker([MogileFS Object], string disable, string level)
	*/
PHP_FUNCTION(mogilefs_checker)
{
	zval *mg_object = getThis();
	MogilefsSock *mogilefs_sock;
	char *disable="off", *level="1",	*request, *response;
	int	disable_len, level_len, request_len, response_len;

	if (mg_object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O|ss", &mg_object,
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

	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}
	request_len = spprintf(&request, 0, "CHECKER domain=%s&disable=%s&level=%s\r\n", mogilefs_sock->domain, disable, level);

	if (mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		RETURN_FALSE;
	}
	efree(request);

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}
	RETURN_TRUE;
}

/* }}} */

/* {{{ proto string mogilefs_monitor_round([MogileFS Object])
	*/
PHP_FUNCTION(mogilefs_monitor_round)
{
	zval *mg_object = getThis();
	MogilefsSock *mogilefs_sock;
	char *request, *response;
	int	request_len, response_len;

	if (mg_object == NULL) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &mg_object,
									mogilefs_class_entry_ptr) == FAILURE) {
			RETURN_FALSE;
		}
	}

	if (mogilefs_sock_get(mg_object, &mogilefs_sock TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}
	request_len = spprintf(&request, 0, "DO_MONITOR_ROUND domain=%s\r\n",	mogilefs_sock->domain);

	if (mogilefs_sock_write(mogilefs_sock, request, request_len TSRMLS_CC) < 0) {
		efree(request);
		RETURN_FALSE;
	}
	efree(request);

	if ((response = mogilefs_sock_read(mogilefs_sock, &response_len TSRMLS_CC)) == NULL) {
		RETURN_FALSE;
	}

	if (mogilefs_parse_response_to_array(INTERNAL_FUNCTION_PARAM_PASSTHRU, response, response_len) < 0) {
		RETURN_FALSE;
	}

	RETURN_TRUE;
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
