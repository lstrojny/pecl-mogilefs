#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION > 2) || PHP_MAJOR_VERSION > 5
# define MOGILEFS_ARG_INFO
#else
# define MOGILEFS_ARG_INFO static
#endif

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

PHP_METHOD(MogileFs, __construct);
PHP_METHOD(MogileFs, isConnected);
PHP_METHOD(MogileFs, connect);
PHP_METHOD(MogileFs, get);
PHP_METHOD(MogileFs, getDomains);
PHP_METHOD(MogileFs, fileInfo);
PHP_METHOD(MogileFs, listKeys);
PHP_METHOD(MogileFs, listFids);
PHP_METHOD(MogileFs, getHosts);
PHP_METHOD(MogileFs, getDevices);
PHP_METHOD(MogileFs, sleep);
PHP_METHOD(MogileFs, stats);
PHP_METHOD(MogileFs, replicate);
PHP_METHOD(MogileFs, createDevice);
PHP_METHOD(MogileFs, createDomain);
PHP_METHOD(MogileFs, deleteDomain);
PHP_METHOD(MogileFs, createClass);
PHP_METHOD(MogileFs, updateClass);
PHP_METHOD(MogileFs, deleteClass);
PHP_METHOD(MogileFs, createHost);
PHP_METHOD(MogileFs, updateHost);
PHP_METHOD(MogileFs, deleteHost);
PHP_METHOD(MogileFs, setWeight);
PHP_METHOD(MogileFs, setState);
PHP_METHOD(MogileFs, checker);
PHP_METHOD(MogileFs, monitorRound);
PHP_METHOD(MogileFs, put);
PHP_METHOD(MogileFs, close);
PHP_METHOD(MogileFs, disconnect);
PHP_METHOD(MogileFs, delete);
PHP_METHOD(MogileFs, rename);
PHP_METHOD(MogileFs, setReadTimeout);
PHP_METHOD(MogileFs, getReadTimeout);
PHP_METHOD(MogileFs, isInDebuggingMode);

static zend_function_entry class_MogileFs_methods[] = {
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
