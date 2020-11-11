# ModSecurity v3 - HAProxy SPOA

This is a [SPOA](https://www.haproxy.com/blog/extending-haproxy-with-the-stream-processing-offload-engine/) for HAProxy 
that adds support for ModSecurity.

This is a heavy WIP, and further information of how to use this will be provided

## Requirements
* libmodsecurity - 
* pymodsecurity - Compilation instructions will be provided later
* HAProxy SPOA Server code to compile the wrapper - https://github.com/haproxy/haproxy/tree/master/contrib/spoa_server

## Usage

* Configure HAProxy according to haproxy.cfg and modsec.conf

* Start the spoa with: 
```
RULES=modsecurity.conf ./spoa -f modsecurity.py
```

* Start the HAProxy with the configuration

## Files in this repository

* The python script - modsecurity.py
* A sample haproxy.cfg and modsec.conf (the SPOE configuration)
* A sample modsecurity.conf rule that blocks all requests originating from 127.0.0.1

## TODO
* Create a Dockerfile with everything
* Create some better docs with the possible usages / configurations (like ignoring rules, which is in the configfile but optional)
* There's a lot of TODO in the code, a lot of improvements
* Better logging, so this can be used with HAProxy Ingress (maybe printing as json with the namespace of the app)
* Turning paranoia level configurable per vhost
* Performance testing, a lot of performance testing (this is not battle tested yet!)

## Thank you
- Manuel Alejandro de Brito (aledbf) - For the idea of using python instead of almost killink myself with Go and CGO
- Joao Morais Junior (jcmoraisjr) - For the valuable support with HAProxy
- The creators of pymodsecurity and django_pymodsecurity, which were base for this script
