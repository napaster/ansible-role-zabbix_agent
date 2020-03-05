# ansible-zabbix_agent

Zabbix agent is deployed on a monitoring target to actively monitor local
resources and applications (hard drives, memory, processor statistics etc).

## Requirements

* Ansible 2.8+;

## Example configuration

```yaml
---
zabbix_agent:
# Enable zabbix-agent service or not.
- enable: 'true'
# Restart zabbix-agent service or not.
  restart: 'true'
# Install zabbix-agent package or not.
  install_package: 'true'
# Install or not prepared scripts from Amazon S3 storage. This may be useful
# for uncompatible 'user_parameter' commands with YAML syntax.
  install_s3_scripts: 'true'
# Amazon S3 Storage settings.
  s3_storage_settings:
# AWS access key id. If not set then the value of the AWS_ACCESS_KEY
# environment variable is used.
    - aws_access_key: "{{ aws_s3_access_key }}"
# AWS secret key. If not set then the value of the AWS_SECRET_KEY environment
# variable is used.
      aws_secret_key: "{{ aws_s3_secret_key }}"
# Bucket name.
      bucket: "{{ aws_s3_bucket }}"
# Time limit (in seconds) for the URL generated and returned by S3.
      expiration: '120'
# Enable fakeS3.
      rgw: "{{ aws_s3_rgw }}"
# S3 URL endpoint for usage with fakeS3. Otherwise assumes AWS.
      s3_url: "{{ aws_s3_url }}"
# When set to 'no', SSL certificates will not be validated.
      validate_certs: "{{ omit }}"
# S3 region.
      region: "{{ omit }}"
# Use this boto profile.
      profile: "{{ omit }}"
# Prefix ('folder') where objects placed in bucket, i.e.:
# s3://ansible/ansible-role-zabbix_agent/*
      object_prefix: 'ansible-role-zabbix_agent'
# Pre-shared key string.
  psk_string: '42a46dc13aff1bc26ba2467779da343614a8bbf1c39780c9819cf24e32d8f279'
# Deploy or not 'psk_string' as '/etc/zabbix/zabbix_agentd.psk' file.
  deploy_psk_file: 'true'
  settings:
#	Name of PID file.
  - pid_file: '/tmp/zabbix_agentd.pid'
#	Specifies where log messages are written to: 'system' - syslog, 'file' - file
# specified with LogFile parameter, 'console' - standard output.
    log_type: 'system'
#	Log file name for LogType 'file' parameter. Mandatory if 'log_type' is set to
# 'file'.
    log_file: '/var/log/zabbix_agent.log'
#	Maximum size of log file in range 0-1024MB. '0' - disable automatic log
# rotation. Default is '1'.
    log_file_size: '1'
#	Specifies debug level:
#	'0' - basic information about starting and stopping of Zabbix processes;
#	'1' - critical information;
#	'2' - error information;
#	'3' - warnings (the default);
#	'4' - for debugging (produces lots of information);
#	'5' - extended debugging (produces even more information);
    debug_level: '3'
#	Source IP address for outgoing connections.
    source_ip: ''
#	Whether remote commands from Zabbix server are allowed.
# '0' - not allowed (the default);
# '1' - allowed;
    enable_remote_commands: '0'
#	Enable logging of executed shell commands as warnings.
# '0' - disabled (the default);
# '1' - enabled;
    log_remote_commands: '0'
#	List of comma delimited IP addresses, optionally in CIDR notation, or DNS
# names of Zabbix servers and Zabbix proxies. Incoming connections will be
# accepted only from the hosts listed here. If IPv6 support is enabled then
# '127.0.0.1', '::127.0.0.1', '::ffff:127.0.0.1' are treated equally and '::/0'
# will allow any IPv4 or IPv6 address. '0.0.0.0/0' can be used to allow any
# IPv4 address.
    server:
    - '127.0.0.1'
    - '192.168.1.0/24'
    - '::1'
    - '2001:db8::/32'
    - 'zabbix.example.com'
#	Agent will listen on this port for connections from the server.
# Default is '10050'.
    listen_port: '10050'
# List of comma delimited IP addresses that the agent should listen on. First
# IP address is sent to Zabbix server if connecting to it to retrieve list of
# active checks.
    listen_ip: '0.0.0.0'
# Number of pre-forked instances (in range of 0-100) of zabbix_agentd that
# process passive checks. If set to '0', disables passive checks and the agent
# will not listen on any TCP port. Default is '3'.
    start_agents: '3'
#	List of comma delimited IP:port (or DNS name:port) pairs of Zabbix servers
# and Zabbix proxies for active checks. If port is not specified, default port
# is used. IPv6 addresses must be enclosed in square brackets if port for that
# host is specified. If port is not specified, square brackets for IPv6
# disabled. Default is None.
    server_active:
    - '127.0.0.1:20051'
    - 'zabbix.domain'
    - '[::1]:30051'
    - '::1'
    - '[12fc::1]'
#	Unique, case sensitive hostname. Required for active checks and must match
# hostname as configured on the server. Value is acquired from HostnameItem if
# undefined.
    hostname: 'r1.example.com'
#	Item used for generating Hostname if it is undefined. Ignored if Hostname is
# defined. Does not support 'user_parameter' or aliases.
    hostname_item: 'system.hostname'
#	Optional parameter that defines host metadata. Host metadata is used at host
# auto-registration process. An agent will issue an error and not start if the
# value is over limit of 255 characters. If not defined, value will be acquired
# from 'host_metadata_item'.
    host_metadata: ''
#	Optional parameter that defines an item used for getting host metadata. Host
# metadata is used at host auto-registration process. During an
# auto-registration request an agent will log a warning message if the value
# returned by specified item is over limit of 255 characters. This option is
# only used when 'host_metadata' is not defined.
    host_metadata_item: ''
#	Optional parameter that defines host interface. Host interface is used at
# host auto-registration process. An agent will issue an error and not start if
# the value is over limit of 255 characters. If not defined, value will be
# acquired from 'host_interface_item'.
    host_interface: ''
#	Optional parameter that defines an item used for getting host interface. Host
# interface is used at host auto-registration process. During an
# auto-registration request an agent will log a warning message if the value
# returned by specified item is over limit of 255 characters. This option is
# only used when 'host_interface' is not defined.
    host_interface_item: ''
#	How often list of active checks is refreshed, in rage 60-3600 seconds.
# Default is '120'.
    refresh_active_checks: '120'
#	Do not keep data longer than N seconds in buffer. Value in range of 1-3600
# seconds. Default is '5'.
    buffer_send: '5'
#	Maximum number of values in a memory buffer. The agent will send all collected
# data to Zabbix Server or Proxy if the buffer is full. Value in range 2-65535.
# Default is '100'.
    buffer_size: '100'
#	Maximum number of new lines the agent will send per second to Zabbix Server or
# Proxy processing 'log' and 'logrt' active checks. The provided value will be
# overridden by the parameter 'maxlines',	provided in 'log' or 'logrt' item
# keys. Value in range 1-1000. Default is '20'.
    max_lines_per_second: '20'
#	Sets an alias for an item key. It can be used to substitute long and complex
# item key with a smaller and simpler one. Multiple Alias parameters may be
# present. Multiple parameters with the same Alias key are not allowed.
# Different Alias keys may reference the same item key. For example, to retrieve
# the ID of user 'zabbix', now shorthand key zabbix.userid may be used to
# retrieve data. Aliases can be used in 'host_metadata_item' but not in
# 'hostname_item' parameters.
    alias: 'zabbix.userid:vfs.file.regexp[/etc/passwd,^zabbix:.:([0-9]+),,,,\1]'
#	Spend no more than timeout seconds (in range 1-30) on processing.
# Default is '3'.
    timeout: '3'
#	Allow the agent to run as 'root'. If disabled and the agent is started by
# 'root', the agent will try to switch to the user specified by the user
# configuration option instead. Has no effect if started under a regular user:
# '0' - do not allow (the default);
# '1' - allow;
    allow_root: '0'
#	Drop privileges to a specific, existing user on the system. Only has effect
# if run as 'root' and 'allow_root' is disabled. Default is 'zabbix'.
    user: 'zabbix'
#	You may include individual files or all files in a directory in the
# configuration file. Default is None.
    include:
    - '/etc/zabbix_agentd.userparams.conf'
    - '/etc/zabbix_agentd.conf.d/'
    - '/etc/zabbix_agentd.conf.d/*.conf'
#	Allow all characters to be passed in arguments to user-defined parameters.
#	The following characters are not allowed:
#	\ ' " ` * ? [ ] { } ~ $ ! & ; ( ) < > | # @
#	Additionally, newline characters are not allowed.
#	'0' - do not allow (the default);
#	'1' - allow;
    unsafe_user_parameters: '0'
#	User-defined parameter to monitor. There can be several user-defined
# parameters. Default is None.
    user_parameter:
    - key: 'ping[*]'
      command: 'echo $1'
    - key: 'mysql.ping[*]'
      command: 'mysqladmin -u$1 -p$2 ping | grep -c alive'
# S3 scripts
    - key: 'isp.Discovery.Check'
      command: 'zabbix_router_isp_check_json.sh'
      s3: 'true'
# Additional params for this command. The items of list will be joined to
# command string, quoted ('"') and splitted via space, eg: '123.sh "$1" "$2"'.
      params:
      - '$1'
      - '$2'
      - '$3'
#	Full path to location of agent modules.Default depends on compilation options.
#	To see the default path run command "zabbix_agentd --help".
    load_module_path: '/usr/lib/modules'
# Module to load at agent startup. Modules are used to extend functionality of
# the agent. Either the module must be located in directory specified by
# 'load_module_path' or the path must precede the module name. If the preceding
# path is absolute (starts with '/') then 'load_module_path' is ignored.
    load_module:
    - 'module.so'
    - 'path/module.so'
    - '/abs_path/module.so'
#	How the agent should connect to server or proxy. Used for active checks. Only
# one value can be specified:
#	'unencrypted' - connect without encryption (the default);
#	'psk' - connect using TLS and a pre-shared key;
#	'cert' - connect using TLS and a certificate;
# This option is mandatory, if TLS certificate or PSK parameters are defined
# (even for 'unencrypted' connection).
    tls_connect: 'unencrypted'
#	What incoming connections to accept. Multiple values can be specified:
#	'unencrypted' - accept connections without encryption (the default);
#	'psk' - accept connections secured with TLS and a pre-shared key;
#	'cert' - accept connections secured with TLS and a certificate;
# This options is mandatory, if TLS certificate or PSK parameters are defined
# (even for 'unencrypted' connection)
    tls_accept: 'unencrypted'
#	Full pathname of a file containing the top-level CA certificates for peer
# certificate verification. Default is None.
    tls_ca_file: ''
#	Full pathname of a file containing revoked certificates. Default is None.
    tls_crl_file: ''
# Allowed server certificate issuer. Default is None.
    tls_server_cert_issuer: ''
#	Allowed server certificate subject. Default is None.
    tls_server_cert_subject: ''
#	Full pathname of a file containing the agent certificate or certificate chain.
# Default is None.
    tls_cert_file: ''
#	Full pathname of a file containing the agent private key. Default is None.
    tls_key_file: ''
#	Unique, case sensitive string used to identify the pre-shared key. Default
# is None.
    tls_psk_identity: 'psk 001'
#	Full pathname of a file containing the pre-shared key. Default is None.
    tls_psk_file: '/etc/zabbix/zabbix_agentd.psk'
```
