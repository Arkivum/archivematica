## Table of contents

- [Introduction](#introduction)
- [Environment variables](#environment-variables)
- [Logging configuration](#logging-configuration)

## Introduction

MCPServer has multiple sources of configuration. This is the full list ordered
by precedence (with the last listed item winning prioritization):

- Application defaults
- Configuration files: (see [`the example`](./serverConfig.conf))
    - `/etc/archivematica/archivematicaCommon/dbsettings` (optional)
    - `/etc/archivematica/MCPServer/serverConfig.conf` (optional)
- Environment variables (always win precedence)

## Environment variables

The value of an environment variable is a string of characters. The
configuration system coerces the value to the types supported:

- `string` (e.g. `"foobar"`)
- `int` (e.g. `"60"`)
- `float` (e.g. `"1.20"`)
- `boolean` where truth values can be represented as follows (checked in a
case-insensitive manner):
    - True (enabled):  `"1"`, `"yes"`, `"true"` or `"on"`
    - False (disabled): `"0"`, `"no"`, `"false"` or `"off"`

Certain environment strings are mandatory, i.e. they don't have defaults and
the application will refuse to start if the user does not provide one.

Please be aware that Archivematica supports different types of distributions
(Ubuntu/CentOS packages, Ansible or Docker images) and they may override some
of these settings or provide values to mandatory fields.

This is the full list of environment strings supported:

- **`ARCHIVEMATICA_MCPSERVER_MCPSERVER_DJANGO_SECRET_KEY`**:
    - **Description:** a secret key used for cryptographic signing. See [SECRET_KEY](https://docs.djangoproject.com/en/1.8/ref/settings/#secret-key) for more details.
    - **Config file example:** `MCPServer.django_secret_key`
    - **Type:** `string`
    - :red_circle: **Mandatory!**

- **`ARCHIVEMATICA_MCPSERVER_MCPSERVER_SHAREDDIRECTORY`**:
    - **Description:** location of the Archivematica Shared Directory.
    - **Config file example:** `MCPServer.sharedDirectory`
    - **Type:** `string`
    - **Default:** `"/var/archivematica/sharedDirectory/"`

- **`ARCHIVEMATICA_MCPSERVER_MCPSERVER_PROCESSINGXMLFILE`**:
    - **Description:** name of the processing configuration file.
    - **Config file example:** `MCPServer.processingXMLFile`
    - **Type:** `string`
    - **Default:** `"processingMCP.xml"`

- **`ARCHIVEMATICA_MCPSERVER_MCPSERVER_MCPARCHIVEMATICASERVER`**:
    - **Description:** address of the Gearman server.
    - **Config file example:** `MCPServer.MCPArchivematicaServer`
    - **Type:** `string`
    - **Default:** `"localhost:4730"`

- **`ARCHIVEMATICA_MCPSERVER_MCPSERVER_WATCHDIRECTORYPATH`**:
    - **Description:** location of the Archivematica Watched Directories.
    - **Config file example:** `MCPServer.watchDirectoryPath`
    - **Type:** `string`
    - **Default:** `"/var/archivematica/sharedDirectory/watchedDirectories/"`

- **`ARCHIVEMATICA_MCPSERVER_MCPSERVER_PROCESSINGDIRECTORY`**:
    - **Description:** loation of the processing directory.
    - **Config file example:** `MCPServer.processingDirectory`
    - **Type:** `string`
    - **Default:** `"/var/archivematica/sharedDirectory/currentlyProcessing/"`

- **`ARCHIVEMATICA_MCPSERVER_MCPSERVER_REJECTEDDIRECTORY`**:
    - **Description:** location of the rejected directory.
    - **Config file example:** `MCPServer.rejectedDirectory`
    - **Type:** `string`
    - **Default:** `"%%sharedPath%%rejected/"`

- **`ARCHIVEMATICA_MCPSERVER_MCPSERVER_WAITONAUTOAPPROVE`**:
    - **Description:** number of seconds that a thread will wait before attempting to approve a chain when it is pre-configured.
    - **Config file example:** `MCPServer.waitOnAutoApprove`
    - **Type:** `int`
    - **Default:** `"0"`

- **`ARCHIVEMATICA_MCPSERVER_MCPSERVER_WATCHDIRECTORIESPOLLINTERVAL`**:
    - **Description:** time in seconds between filesystem poll intervals .
    - **Config file example:** `MCPServer.watchDirectoriesPollInterval`
    - **Type:** `int`
    - **Default:** `"1"`

- **`ARCHIVEMATICA_MCPSERVER_PROTOCOL_LIMITTASKTHREADS`**:
    - **Description:** max. number of threads that MCPServer will run simultaneously.
    - **Config file example:** `protocol.limitTaskThreads`
    - **Type:** `int`
    - **Default:** `"75"`

- **`ARCHIVEMATICA_MCPSERVER_PROTOCOL_LIMITTASKTHREADSSLEEP`**:
    - **Description:** number of seconds that the application will wait before trying to start a new thread when the limit is reached.
    - **Config file example:** `protocol.limitTaskThreadsSleep`
    - **Type:** `float`
    - **Default:** `"0.2"`

- **`ARCHIVEMATICA_MCPSERVER_PROTOCOL_LIMITGEARMANCONNECTIONS`**:
    - **Description:** max. number of concurrent connections to Gearman server.
    - **Config file example:** `protocol.limitGearmanConnections`
    - **Type:** `int`
    - **Default:** `"10000"`

- **`ARCHIVEMATICA_MCPSERVER_PROTOCOL_RESERVEDASTASKPROCESSINGTHREADS`**:
    - **Description:** max. number of concurrent processing threads running foreground Gearman jobs.
    - **Config file example:** `protocol.reservedAsTaskProcessingThreads`
    - **Type:** `int`
    - **Default:** `"8"`

- **`ARCHIVEMATICA_MCPSERVER_CLIENT_ENGINE`**:
    - **Description:** a database setting. See [DATABASES](https://docs.djangoproject.com/en/1.8/ref/settings/#databases) for more details.
    - **Config file example:** `client.engine`
    - **Type:** `string`
    - **Default:** `django.db.backends.mysql`

- **`ARCHIVEMATICA_MCPSERVER_CLIENT_DATABASE`**:
    - **Description:** a database setting. See [DATABASES](https://docs.djangoproject.com/en/1.8/ref/settings/#databases) for more details.
    - **Config file example:** `client.database`
    - **Type:** `string`
    - **Default:** `MCP`

- **`ARCHIVEMATICA_MCPSERVER_CLIENT_USER`**:
    - **Description:** a database setting. See [DATABASES](https://docs.djangoproject.com/en/1.8/ref/settings/#databases) for more details.
    - **Config file example:** `client.user`
    - **Type:** `string`
    - **Default:** `archivematica`

- **`ARCHIVEMATICA_MCPSERVER_CLIENT_PASSWORD`**:
    - **Description:** a database setting. See [DATABASES](https://docs.djangoproject.com/en/1.8/ref/settings/#databases) for more details.
    - **Config file example:** `client.password`
    - **Type:** `string`
    - **Default:** `demo`

- **`ARCHIVEMATICA_MCPSERVER_CLIENT_HOST`**:
    - **Description:** a database setting. See [DATABASES](https://docs.djangoproject.com/en/1.8/ref/settings/#databases) for more details.
    - **Config file example:** `client.host`
    - **Type:** `string`
    - **Default:** `localhost`

- **`ARCHIVEMATICA_MCPSERVER_CLIENT_PORT`**:
    - **Description:** a database setting. See [DATABASES](https://docs.djangoproject.com/en/1.8/ref/settings/#databases) for more details.
    - **Config file example:** `client.port`
    - **Type:** `string`
    - **Default:** `3306`

## Logging configuration

Archivematica 1.6.1 and earlier releases are configured by default to log to
subdirectories in `/var/log/archivematica`, such as
`/var/log/archivematica/MCPServer/MCPServer.debug.log`. Starting with
Archivematica 1.7.0, logging configuration defaults to using stdout and stderr
for all logs. If no changes are made to the new default configuration, logs
will be handled by whichever process is managing Archivematica's services. For
example on Ubuntu 16.04 or Centos 7, Archivematica's processes are managed by
systemd. Logs for the MCPServer can be accessed using
`sudo journalctl -u archivematica-mcp-server`. On Ubuntu 14.04, upstart is used
instead of systemd, so logs are usually found in `/var/log/upstart`. When
running Archivematica using docker, `docker-compose logs` commands can be used
to access the logs from different containers.

The MCPServer will look in `/etc/archivematica` for a file called
`serverConfig.logging.json`, and if found, this file will override the default
behaviour described above.

The [`serverConfig.logging.json`](./serverConfig.logging.json) file in this
directory provides an example that implements the logging behaviour used in
Archivematica 1.6.1 and earlier.