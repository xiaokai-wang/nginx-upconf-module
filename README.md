Name
====

nginx-upconf-module - Nginx C module, provides an HTTP interface for adding, removing, and modifying back-end servers dynamically and without having to reload the configuration, seems like Nginx-Plus ngx_http_upstream_conf_module.

It may not always be convenient to modify configuration files and restart NGINX. For example, if you are experiencing large amounts of traffic and high load, restarting NGINX and reloading the configuration at that point further increases load on the system and can temporarily degrade performance.

The module can be more smoothly expansion and constriction, and will not influence the performance.

Table of Contents
=================

* [Name](#name)
* [Status](#status)
* [Synopsis](#synopsis)
* [Description](#description)
* [Directives](#functions)
    * [upstream_conf](#upstream_conf)
    * [upconf_dump_path](#upconf_dump_path)
    * [upstream_show](#upstream_show)
* [Compatibility](#compatibility)
* [Installation](#installation)
* [Author](#author)
* [Copyright and License](#copyright-and-license)
* [Dependency](#dependency)

Status
======

This module is still under active development.

Synopsis
========

```nginx
http {
    upstream test {
        upconf_dump_path /usr/local/nginx/conf/servers/servers_test.conf;

        server 127.0.0.1:8089 weight=1, fail_timeout=10, max_fails=3;
    }

    upstream bar {
        server 127.0.0.1:8090 weight=1, fail_timeout=10, max_fails=3;
    }

    server {
        listen 8080;

        location = /proxy_test {
            proxy_pass http://test;
        }

        location = /bar {
            proxy_pass http://bar;
        }

        location = /upstream_conf {
            upstream_conf;
        }

        location = /upstream_show {
            upstream_show;
        }

    }
}
```

Description
======

On-The-Fly Configuration Using an HTTP-based API:

* timely

      effective in a minute.

* performance

      http api, like a request to nginx, updating ip router nginx needn't reload, so affecting nginx performance is little.

* availability

      support dumping servers to local, so you can reload nginx anytime, will keep service high available.

* health_check

      nginx-upconf-module support adding or deleting servers health check, needing nginx_upstream_check_module. Recommending nginx-upsync-module + nginx_upstream_check_module.

Diretives
======

upstream_conf
-----------
```
syntax: upstream_conf
```
default: none

context: location

description: just like the [Description](http://nginx.org/en/docs/http/ngx_http_upstream_conf_module.html#upstream_conf)

[Back to TOC](#table-of-contents)       

upconf_dump_path
-----------
`syntax: upconf_dump_path $path`

default: /usr/local/nginx/conf/servers/servers_$host.conf

context: upstream

description: dump the upstream backends to the $path.

[Back to TOC](#table-of-contents)       

Compatibility
=============

The module was developed base on nginx1.8.0.

Compatible with Nginx-1.8.x.

Compatible with Nginx-1.9.x.

[Back to TOC](#table-of-contents)

Installation
============

This module can be used independently, can be download[Github](https://github.com/xiaokai-wang/nginx-upconf-module.git).

Grab the nginx source code from [nginx.org](http://nginx.org/), for example, the version 1.8.0 (see nginx compatibility), and then build the source with this module:

```bash
wget 'http://nginx.org/download/nginx-1.8.0.tar.gz'
tar -xzvf nginx-1.8.0.tar.gz
cd nginx-1.8.0/
```

```bash
./configure --add-module=/path/to/ngx_sync_msg_module --add-module=/path/to/nginx-upconf-module
make
make install
```

[Back to TOC](#table-of-contents)

Author
======

Xiaokai Wang (王晓开) <xiaokai.wang@live.com>, Weibo Inc.

[Back to TOC](#table-of-contents)

Copyright and License
=====================

This README template copy from agentzh.

This module is licensed under the BSD license.

Copyright (C) 2014 by Xiaokai Wang <xiaokai.wang@live.com></xiaokai.wang@live.com>

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

[Back to TOC](#table-of-contents)

dependency
========
* ngx_sync_msg_module: https://github.com/yzprofile/ngx_sync_msg_module

[back to toc](#table-of-contents)


