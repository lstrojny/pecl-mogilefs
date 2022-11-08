/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: 8a8afeda08b8f271787a1ed1f1f555153b4cb044 */

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_MogileFs___construct, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_MogileFs_isConnected, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_MogileFs_connect, 0, 4, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, host, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, port, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, domain, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, timeout, IS_DOUBLE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_MogileFs_get, 0, 1, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, pathcount, IS_LONG, 0, "2")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_MogileFs_getDomains, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_MogileFs_fileInfo, 0, 1, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_MogileFs_listKeys, 0, 3, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO(0, prefix, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, after, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, limit, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_MogileFs_listFids, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, from, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, to, IS_LONG, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_MogileFs_getHosts arginfo_class_MogileFs_getDomains

#define arginfo_class_MogileFs_getDevices arginfo_class_MogileFs_getDomains

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_MogileFs_sleep, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, duration, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_MogileFs_stats, 0, 1, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO(0, all, IS_LONG, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_MogileFs_replicate arginfo_class_MogileFs_isConnected

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_MogileFs_createDevice, 0, 2, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO(0, devid, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, status, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_MogileFs_createDomain, 0, 1, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO(0, domain, IS_STRING, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_MogileFs_deleteDomain arginfo_class_MogileFs_createDomain

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_MogileFs_createClass, 0, 3, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO(0, domain, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, class, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, mindevcount, IS_STRING, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_MogileFs_updateClass arginfo_class_MogileFs_createClass

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_MogileFs_deleteClass, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, domain, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, class, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_MogileFs_createHost, 0, 1, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO(0, hostname, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_MogileFs_updateHost, 0, 3, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO(0, hostname, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, ip, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, port, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, state, IS_STRING, 0, "\"alive\"")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_MogileFs_deleteHost, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, hostname, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_MogileFs_setWeight, 0, 3, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, hostname, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, device, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, weight, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_MogileFs_setState, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, hostname, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, device, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, state, IS_STRING, 0, "\"alive\"")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_MogileFs_checker, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, status, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, level, IS_STRING, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_MogileFs_monitorRound arginfo_class_MogileFs_getDomains

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_MogileFs_put, 0, 3, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, pathvalidfile, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, class, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, use_file, _IS_BOOL, 0, "true")
ZEND_END_ARG_INFO()

#define arginfo_class_MogileFs_close arginfo_class_MogileFs_isConnected

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_MogileFs_delete, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_MogileFs_rename, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, from_key, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, to_key, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_MogileFs_setReadTimeout, 0, 1, IS_VOID, 0)
	ZEND_ARG_TYPE_INFO(0, readTimeout, IS_DOUBLE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_MogileFs_getReadTimeout, 0, 0, IS_DOUBLE, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_MogileFs_isInDebuggingMode arginfo_class_MogileFs_isConnected

#define arginfo_class_MogileFs_disconnect arginfo_class_MogileFs_isConnected


ZEND_METHOD(MogileFs, __construct);
ZEND_METHOD(MogileFs, isConnected);
ZEND_METHOD(MogileFs, connect);
ZEND_METHOD(MogileFs, get);
ZEND_METHOD(MogileFs, getDomains);
ZEND_METHOD(MogileFs, fileInfo);
ZEND_METHOD(MogileFs, listKeys);
ZEND_METHOD(MogileFs, listFids);
ZEND_METHOD(MogileFs, getHosts);
ZEND_METHOD(MogileFs, getDevices);
ZEND_METHOD(MogileFs, sleep);
ZEND_METHOD(MogileFs, stats);
ZEND_METHOD(MogileFs, replicate);
ZEND_METHOD(MogileFs, createDevice);
ZEND_METHOD(MogileFs, createDomain);
ZEND_METHOD(MogileFs, deleteDomain);
ZEND_METHOD(MogileFs, createClass);
ZEND_METHOD(MogileFs, updateClass);
ZEND_METHOD(MogileFs, deleteClass);
ZEND_METHOD(MogileFs, createHost);
ZEND_METHOD(MogileFs, updateHost);
ZEND_METHOD(MogileFs, deleteHost);
ZEND_METHOD(MogileFs, setWeight);
ZEND_METHOD(MogileFs, setState);
ZEND_METHOD(MogileFs, checker);
ZEND_METHOD(MogileFs, monitorRound);
ZEND_METHOD(MogileFs, put);
ZEND_METHOD(MogileFs, close);
ZEND_METHOD(MogileFs, delete);
ZEND_METHOD(MogileFs, rename);
ZEND_METHOD(MogileFs, setReadTimeout);
ZEND_METHOD(MogileFs, getReadTimeout);
ZEND_METHOD(MogileFs, isInDebuggingMode);


static const zend_function_entry class_MogileFs_methods[] = {
	ZEND_ME(MogileFs, __construct, arginfo_class_MogileFs___construct, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, isConnected, arginfo_class_MogileFs_isConnected, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, connect, arginfo_class_MogileFs_connect, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, get, arginfo_class_MogileFs_get, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, getDomains, arginfo_class_MogileFs_getDomains, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, fileInfo, arginfo_class_MogileFs_fileInfo, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, listKeys, arginfo_class_MogileFs_listKeys, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, listFids, arginfo_class_MogileFs_listFids, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, getHosts, arginfo_class_MogileFs_getHosts, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, getDevices, arginfo_class_MogileFs_getDevices, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, sleep, arginfo_class_MogileFs_sleep, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, stats, arginfo_class_MogileFs_stats, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, replicate, arginfo_class_MogileFs_replicate, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, createDevice, arginfo_class_MogileFs_createDevice, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, createDomain, arginfo_class_MogileFs_createDomain, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, deleteDomain, arginfo_class_MogileFs_deleteDomain, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, createClass, arginfo_class_MogileFs_createClass, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, updateClass, arginfo_class_MogileFs_updateClass, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, deleteClass, arginfo_class_MogileFs_deleteClass, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, createHost, arginfo_class_MogileFs_createHost, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, updateHost, arginfo_class_MogileFs_updateHost, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, deleteHost, arginfo_class_MogileFs_deleteHost, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, setWeight, arginfo_class_MogileFs_setWeight, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, setState, arginfo_class_MogileFs_setState, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, checker, arginfo_class_MogileFs_checker, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, monitorRound, arginfo_class_MogileFs_monitorRound, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, put, arginfo_class_MogileFs_put, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, close, arginfo_class_MogileFs_close, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, delete, arginfo_class_MogileFs_delete, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, rename, arginfo_class_MogileFs_rename, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, setReadTimeout, arginfo_class_MogileFs_setReadTimeout, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, getReadTimeout, arginfo_class_MogileFs_getReadTimeout, ZEND_ACC_PUBLIC)
	ZEND_ME(MogileFs, isInDebuggingMode, arginfo_class_MogileFs_isInDebuggingMode, ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
	ZEND_MALIAS(MogileFs, disconnect, close, arginfo_class_MogileFs_disconnect, ZEND_ACC_PUBLIC)
	ZEND_FE_END
};
