<?php

define('MOGILEFS_WEBDAV', 1);
define('MOGILEFS_CURL',   2);

Class Mogilefs
{
    static $domain;
    static $use_webdav;
    static $use_curl;

    function Mogilefs($domain, $storage = MOGILEFS_CURL) {
        $this->domain = $domain;
        if($storage === MOGILEFS_WEBDAV) { 
            if(extension_loaded('webdav') === FALSE) {
                die("MOGILEFS_WEBDAV need webdav extension\n");
            }
            return ($this->use_webdav = 1);
        }
        if($storage === MOGILEFS_CURL) { 
            if(extension_loaded('curl') === FALSE) {
                die("MOGILEFS_CURL need curl extension\n");
            }
            return ($this->use_curl = 1);
        }
        die("Mogilefs need webdav or curl extension\n");
    }

    function init($servers) {
        if(is_array($servers) === FALSE) {
            $servers = array($servers);
        }
        shuffle($servers);

        foreach($servers as $server) {
            list($ip, $port) = split(':', $server, 2);
            if(mogilefs_connect($ip, $port, 
                                $this->domain) === TRUE) {
                break;
            }    
        }
    }

    function store_with_curl($path, $filename) {
        $ptr_file = fopen($filename, 'r');

        $curl = curl_init();
        curl_setopt($curl, CURLOPT_PUT, 1);
        curl_setopt($curl, CURLOPT_URL, rtrim($path));
        curl_setopt($curl, CURLOPT_VERBOSE, 0);
        curl_setopt($curl, CURLOPT_INFILE, $ptr_file);
        curl_setopt($curl, CURLOPT_INFILESIZE, filesize($filename));
        curl_setopt($curl, CURLOPT_TIMEOUT, 4);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);

        if(!curl_exec($curl)) {
            fclose($ptr_file);
            curl_close($curl);
            return -1;
        }
        fclose($ptr_file);
        curl_close($curl);
        return 0;
    }

    function store($key, $class, $filename, $multi_dest = 0) {
        if(($res = mogilefs_create_open($key, $class, 
                                        $multi_dest)) === FALSE) {
            return FALSE;
        }
        
        if($multi_dest != 0) {
            # XXX: support multi_dest.
            die("multi_dest non supporté\n");
        }

        if(empty($res['path']) || empty($res['devid']) ||
            empty($res['fid'])) {
            return FALSE;
        }

        if($this->use_curl == 1) {
            if($this->store_with_curl($res['path'], 
                                      $filename) < 0) {
                return FALSE;
            }                          
        } elseif($this->user_webdav == 1) {    
            #XXX: support WEBDAV
            die("webdav non supporté\n");
        }    
        return mogilefs_create_close($key, $class, urlencode(rtrim($res['path'])),
                                 $res['devid'], $res['fid']);
    }

    function get($key) {
        $res = mogilefs_get_paths($key);
        if(empty($res['path1'])) return FALSE;
        return $res['path1'];
    }
    function delete($key) {
        return mogilefs_delete($key);
    }
}

?>
