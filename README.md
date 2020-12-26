# ModSecurity v3 - HAProxy SPOA

This is a [SPOA](https://www.haproxy.com/blog/extending-haproxy-with-the-stream-processing-offload-engine/) for HAProxy 
that adds support for ModSecurity.

This is a heavy WIP, and further information of how to use this will be provided

## Requirements
* libmodsecurity - 
* pymodsecurity - Compilation instructions will be provided later
* HAProxy SPOA Server code to compile the wrapper - https://github.com/haproxy/haproxy/tree/master/contrib/spoa_server

## How it works
HAProxy have a feature called [SPOE](https://www.haproxy.org/download/1.7/doc/SPOE.txt) 
that allows you to create extensions for it. SPOE can be used to mirror traffic,
and also to take decisions. 

This project is an agent for SPOE (SPOA), that receives transactions from HAProxy 
and validate them against ModSecurity rules.

The base code of Python SPOA agent can be found in [HAProxy Repo](https://github.com/haproxy/haproxy/tree/master/contrib/spoa_server), but this project
already have a [Dockerfile](Dockerfile) that compiles everything.

The SPOA code then calls the Python script with the arguments, and the Python script
validates the request and returns a variable called ``sess.modsec.intervention`` from the SPOA.

This variable returns 0 (false) if no blocking/intervention is needed, and 1 (true) if there's a need of intervention.

This way this can be used in HAProxy to validate requests against the WAF and block or only alert.


## Usage

* Configure HAProxy according to haproxy.cfg and modsec.conf
Obs.: You can configure in the way it fits better, just remember to put the call to the spoa agent.

* Start the spoa with: 
```
RULES=rules/block-localhost.conf ./spoa -f modsecurity.py
```

* Start the HAProxy with the configuration

## Configuring Rules

Rules can be configured as mod security rules, and pointed to the SPOA with
the env RULES.

The example rules only blocks calls from localhost. You can also use the 
coreruleset[https://github.com/coreruleset/coreruleset] to have a better blocking and rules. 

To use the complete rules:

* Download [modsecurity.conf-recommended](https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended) and change according (modify the parameters bellow but keep the others with the default)

```
SecRuleEngine On
[....]

Include coreruleset/crs-setup.conf
Include coreruleset/rules/*.conf
```

* Download the [unicode.mapping] to the same directory

* In the downloaded coreruleset directory, make a copy of crs-setup.conf.example to crs-setup.conf and make the following changes:


```
# Comment the following lines
# SecDefaultAction "phase:1,log,auditlog,pass"
# SecDefaultAction "phase:2,log,auditlog,pass"  

# Uncomment the following lines, this way modsecurity will work per rule (and not per group of rules)
SecDefaultAction "phase:1,log,auditlog,deny,status:403" 
SecDefaultAction "phase:2,log,auditlog,deny,status:403" 
[...]
# Uncomment and change to paranoia 2
SecAction \
 "id:900000,\
  phase:1,\
  nolog,\
  pass\
  t:none\
  setvar:tx.paranoia_level=2"  
```


## Ignoring Rules per frontend

Rules can be ignored per frontend. Because the agent is called before the backend 
and even before everything is opened, it must be a transaction variable.

This can be configured as the following:

```
frontend myproxy
    [...]

    # You can separate ignored rules with a space
    tcp-request content set-var(txn.ignorerules) str('930201 99999')

    # Declare filter and its config file
    filter spoe engine modsecurity config modsec.conf

    # Reject connection if the intervention is true
    http-request deny if { var(sess.modsec.intervention) -m bool }
    
    [...]
```


## Files in this repository

* The python script - modsecurity.py
* A sample haproxy.cfg and modsec.conf (the SPOE configuration)
* A sample modsecurity.conf rule that blocks all requests originating from 127.0.0.1

## TODO
* Deal with process interruption vs CPU usage

* Prometheus Exporter -> This is going to be nice!!

Metrics of transactions blocked per rule, per host:port, time of transaction, amount of invalid requests.

* Performance testing, a lot of performance testing (this is not battle tested yet!)

## Thank you
- Manuel Alejandro de Brito (aledbf) - For the idea of using python instead of almost killink myself with Go and CGO
- Joao Morais Junior (jcmoraisjr) - For the valuable support with HAProxy
- The creators of libModSecurity who are amazing people and are helping me and others a lot to make this project possible!
- The creators of pymodsecurity and django_pymodsecurity, which were base for this script
