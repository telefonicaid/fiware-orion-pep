# fiware-pep-steelskin

[![FIWARE Security](https://nexus.lab.fiware.org/static/badges/chapters/security.svg)](https://www.fiware.org/developers/catalogue/)
[![License: APGL](https://img.shields.io/github/license/telefonicaid/fiware-pep-steelskin.svg)](https://opensource.org/licenses/AGPL-3.0)
[![Quay badge](https://img.shields.io/badge/quay.io-fiware%2Fpep--steelskin-grey?logo=red%20hat&labelColor=EE0000)](https://quay.io/repository/fiware/pep-steelskin)
[![Docker badge](https://img.shields.io/badge/docker-telefonicaiot%2Ffiware--pep--steelskin-blue?logo=docker)](https://hub.docker.com/r/telefonicaiot/fiware-pep-steelskin)
<br/>
[![CI](https://github.com/telefonicaid/fiware-pep-steelskin/workflows/CI/badge.svg)](https://github.com/telefonicaid/fiware-pep-steelskin/actions?query=workflow%3ACI)
[![Coverage Status](https://coveralls.io/repos/github/telefonicaid/fiware-pep-steelskin/badge.svg?branch=master)](https://coveralls.io/github/telefonicaid/fiware-pep-steelskin?branch=master)
![Status](https://nexus.lab.fiware.org/static/badges/statuses/incubating.svg)

## Index

* [Overview](#overview)
* [Deployment](#deployment)
* [Usage](#usage)
* [Administration](#administration)
* [Configuration](#configuration)
* [API With Access Control](#apiaccesscontrol)
* [Rules to determine the Context Broker action from the request](#rules)
* [Rules to determine the Perseo action from the request](#rulesPerseo)
* [Rules to determine the Keypass Access Control action from the request](#rulesKeypass)
* [Customizing PEP Proxy for other components](#customizing)
* [License](#licence)
* [Development documentation](#development)

## <a name="overview"/> Overview
The Policy Enforcement Point (PEP) is a proxy meant to secure independent FiWare components, by intercepting every request sent to the component, validating it against the Access Control component. This validation is based in several pieces of data:

* User token: comes from the OAuth authorization server and is taken from the `x-auth-token` header.
* ServiceId: is read from the `fiware-service` header and identifies the protected component.
* SubserviceId: is read from the `fiware-servicepath` header and identifies further divisions of the service.
* Action: the PEP guess the action for a particular request by checking the path or inspecting the body. The logic for performing such actions depends on the component that is being secured, so the PEP will need a plugin for each of this components.

Communication with the Access Control is based on the [XACML protocol](http://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html).

Along this document, the term IDM (Identity Manager) will be used, as a general term to refer to the server providing user and role creation and authentication. The currently supported IDM is Keystone; a Keyrock IDM option is provided as well, but it may be deprecated in the near future.

Three other documents provide further information about the PEP Proxy:

* [Operations Manual](operations.md): provides information on logs and alarms.
* [Architecture information](architecture.md): provides further information on how the PEP works and is structured.
* [Keystone installation](keystoneInstallation.md): provides an example of Keystone installation with services and subservices
 that can be used to test the PEP Proxy and play with its features.

## <a name="deployment"/> Deployment
### Dependencies
The PEP Proxy is standard Node.js app and doesn't require more dependencies than the Node.js interpreter and the NPM package utility.

Just checkout this directory and install the Node.js dependencies using:

```
npm install --production
```

The proxy should be then ready to be configured and used.

### With Docker
There are automatic builds of the development version of the Steelskin PEP Proxy published in Docker hub. In order to install
using the docker version, just execute the following:
```
docker run -p 11211:11211 -p 1026:1026 -e LOG_LEVEL=DEBUG -e AUTHENTICATION_HOST=<Keystone-host> -e ACCESS_HOST=<Access-control-host> -e TARGET_HOST=<Orion-host> telefonicaiot/fiware-pep-steelskin
```
This command will create a docker container with a PEP Steelskin running, using <Keystone-host> for token validation and
authentication, <Access-control-host> for access control and redirecting allowed requests to <Orion-host>. Remember there
are more environment variables you can use to tailor Steelskin configuration to suit your needs; you can find the complete
list in the configuration section below.

Take note that this command expose two ports: the 1026 port for component requests and the administration port, 11211.

### Build your own Docker image
There is also the possibility to build your own local Docker image of the PEP component.

To do it, follow the next steps once you have installed Docker in your machine:

1. Navigate to the path where the component repository was cloned.
2. Launch a Docker build
    * Using the default NodeJS version of the operating system used defined in FROM keyword of Dockerfile:
    ```bash
    sudo docker build -f Dockerfile .
    ```
    * Using an alternative NodeJS version:
    ```bash
    sudo docker build --build-arg NODEJS_VERSION=0.10.46 -f Dockerfile .
    ```
### Using PM2

The PEP within the Docker image can be run encapsulated within the [pm2](http://pm2.keymetrics.io/) Process
Manager by adding the `PM2_ENABLED` environment variable.

```console
docker run --name pep -e PM2_ENABLED=true -d fiware/fiware-pep-steelskin
```

Use of pm2 is **disabled** by default. It is unnecessary and counterproductive to add an additional process manager if
your dockerized environment is already configured to restart Node.js processes whenever they exit (e.g. when using
[Kubernetes](https://kubernetes.io/))


### Using Node Inspection

The PEP within the Docker image can be run with [node inspection](https://nodejs.org/en/docs/guides/debugging-getting-started/) by adding the `INSPECT_ENABLED` environment variable.

```console
docker run --name pep -e INSPECT_ENABLED=true -d fiware/fiware-pep-steelskin
```

Use of node inspection is **disabled** by default.

### Undeployment
In order to undeploy the proxy, if it was installed directly from the GIT repositories, just kill the process and remove the directory.

### Configuration
Assuming the PEP Proxy is deployed directly from the source code, it won't add itself as a service, and the running ports should be configured manually. This configuration will involve two steps:
* Changing the port of the Context Broker to a different internal port (not open to external connections). Refer to the Orion Context Broker Deployment Manual for instructions on how to do it.
* Changing the port of the proxy to listen in the Context Broker original port, and to redirect to the new one. This parameters can be changed in the config.js file in the root folder.
Once configured, the service can be started as a demon with the following comand:

```
nohup bin/pep-proxy.js &> pep-proxy.log&
```

### Activate service
The proxy service is disabled once its installed. In order to enable it, use the following command:
```
service pepProxy start
```

### Log Rotation
Independently of how the service is installed, the log files will need an external rotation (e.g.: the logrotate command) to avoid disk full problems. 


## <a name="usage"/> Usage
If the PEP Proxy is not started as a service, it can be started executing the following command from the project root:

```
bin/pep-proxy.js
```

Once the PEP Proxy is working, it can be used to enforce both authentication and authorization over the protected component (e.g. Orion Context Broker). In order to enforce both actions, the PEP Proxy has to be connected to an [Identity Manager](https://github.com/ging/fi-ware-idm) server and an [Access Manager](https://github.com/telefonicaid/fiware-keypass) server. Next sections will show some examples of both processes.

Note that, in order for a request to be authorized through the Access Control, it's mandatory that it contains all of the following headers:
* **x-auth-token**: should contain a valid user token, generated by the IDM.
* **fiware-service**: should contain the name of a service created in the IDM and the user must have access to it.
* **fiware-servicepath**: should contain a route to a subservice, begining with a slash '/' symbol.

This headers are used by the IDM and Access Control systems to make the decisions about the request, so if any of them are missing, the request will not progress any further, and will be rejected with a 400 HTTP error code. For a detailed explanation of the returned errors, please refer to the [API Error codes](errorcodes.md).

The proxy can also work in an authentication-only mode (using the `config.access.disable` flag), in which case the `fiware-service` and `fiware-servicepath` headers can be marked as optional, or checked anyway for validity (controlled by the `config.authentication.checkHeaders` flag). Header checking cannot be disabled for PEP Proxies performing authorization processes.

### Authentication

The authentication process is based on OAuth v2 tokens. The PEP Proxy expects all the requests to have a header `x-auth-token` containing a valid access token from the IDM. All the requests without this requirement are rejected with a 401 error. 

PEP Proxy currently supports two possible authentication authorities: Keyrock IdM and Openstack Keystone. The following sections show how to retrieve a token with each of this authentication technologies. The module can be configured using the config.authentication.module option.

#### Keyrock IdM

In order to get an access token to send with the request, a user can send a request to the IDM, with its user and password (here shown as a curl request):

```
curl -i --user <serverUser>:<serverPassword> -X POST -H "Content-Type: application/x-www-form-urlencoded" https://<idmHostName>/oauth2/token -d 'grant_type=password&username=<theUserName>&password=<theUserPassword>'
```

If the user and password are correct, the response will be like the following:

```
{
    "access_token":"O-OqiBR1AbZk7qfyidF3AwMeBY253xYEpUdkv",
    "refresh_token":"Ny0OwE19230QfftxXYGwwgOLafa5v2xnI5t6HWdQ",
    "token_type":"bearer",
    "expires_in":2591999
}
```

The `access_token` field contains the required token. 

The must be used also to assign roles to each user. For details about role creation and assign, check the IDM API.

#### Keystone
In order to get its access token, a user can send the following request to Keystone:
```
curl http://localhost:5000/v3/auth/tokens \
    -s \
    -i \
    -H "Content-Type: application/json" \
    -d '
{
    "auth": {
        "identity": {
            "methods": [
                "password"
            ],
            "password": {
                "user": {
                    "domain": {
                        "name": "SmartCity"
                    },
                    "name": "alice",
                    "password": "password"
                }
            }
        }
    }
}'
```
The token can be found in the `X-Subject-Token` header of the response:
```
X-Subject-Token: MIIC3AYJKoZIhvcNAQcCoIICzTCCAskCAQExCTAHBgUrDgMCGjCCATIGCSqGSIb3DQEHAaCCASMEggEfeyJ0b2tlbiI6IHsiaXNzdWVkX2F0IjogIjIwMTQtMTAtMTBUMTA6NTA6NDkuNTMyNTQyWiIsICJleHRyYXMiOiB7fSwgIm1ldGhvZHMiOiBbInBhc3N3b3JkIl0sICJleHBpcmVzX2F0IjogIjIwMTQtMTAtMTBUMTE6NTA6NDkuNTMyNDkxWiIsICJ1c2VyIjogeyJkb21haW4iOiB7ImlkIjogImY3YTViOGUzMDNlYzQzZThhOTEyZmUyNmZhNzlkYzAyIiwgIm5hbWUiOiAiU21hcnRWYWxlbmNpYSJ9LCAiaWQiOiAiNWU4MTdjNWUwZDYyNGVlNjhkZmI3YTcyZDBkMzFjZTQiLCAibmFtZSI6ICJhbGljZSJ9fX0xggGBMIIBfQIBATBcMFcxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVVbnNldDEOMAwGA1UEBwwFVW5zZXQxDjAMBgNVBAoMBVVuc2V0MRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20CAQEwBwYFKw4DAhowDQYJKoZIhvcNAQEBBQAEggEAKRGV3uu8fiS7UNm47KhltSjlY1e7KnedUcD-mdwz6Asbo7X9hbtljy1ml9gGcuMf6vX4tycx4goRyMARPS7YKROd0evZtnYArIyx0IrmwDaqodwp8BxBCxFgHRZtCwzHvZFEaUcClydQq7HJvBfTgTwH4v1aJkMyK8wLMP-CYyiZSfCIWPVnoB9I3P56jeKHkmcryYLgT2I-AwDBj1zd9HPzUjyQuNj5rCMkJjvz-A9-hef6AMMZuYPMIYdkei+deq86O1qFuo7PpO2SA7QWkqjcsKs9v+myvHhLrBre9GLP2hP1rc4D67lSL2XB1UY20mc6FNIVIErxT0DOSXltXQ==
Vary: X-Auth-Token
Content-Type: application/json
Content-Length: 287
Date: Fri, 10 Oct 2014 10:50:49 GMT

{
  "token": {
    "issued_at": "2014-10-10T10:50:49.532542Z",
    "extras": {},
    "methods": [
      "password"
    ],
    "expires_at": "2014-10-10T11:50:49.532491Z",
    "user": {
      "domain": {
        "id": "f7a5b8e303ec43e8a912fe26fa79dc02",
        "name": "SmartValencia"
      },
      "id": "5e817c5e0d624ee68dfb7a72d0d31ce4",
      "name": "alice"
    }
  }
}
```

For details on user and role creation, check the Keystone API.

### Authorization

Once the user is authenticated, the PEP Proxy will ask the Access Control for its permissions. In order for the request to be accepted, at least one rule has to match the request information and the user roles. 

Rules are defined in [XACML](https://www.oasis-open.org/committees/xacml/). The particular rules will depend on each case and are left to the authorization designer. The following document shows a typical rule explained for the use case of a Context Broker:

```
<Policy xsi:schemaLocation="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17
    http://docs.oasis-open.org/xacml/3.0/xacml-core-v3-schema-wd-17.xsd"
        PolicyId="policy03"
        RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit"
        Version="1.0" xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">

  <Target>
    <AnyOf>
      <AllOf>
        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-regexp-match">
          <AttributeValue
              DataType="http://www.w3.org/2001/XMLSchema#string"
              >frn:contextbroker:551:833:.*</AttributeValue>
          <AttributeDesignator
              AttributeId="urn:oasis:names:tc:xacml:1.0:resource:resource-id"
              DataType="http://www.w3.org/2001/XMLSchema#string"
              MustBePresent="true"
              Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource" />
        </Match>
      </AllOf>
    </AnyOf>
  </Target>

  <Rule RuleId="policy03rule01" Effect="Permit">

    <Condition>
      <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
        <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-one-and-only">
          <AttributeDesignator
              AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id"
              DataType="http://www.w3.org/2001/XMLSchema#string"
              MustBePresent="true"
              Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action" />
        </Apply>
        <AttributeValue
            DataType="http://www.w3.org/2001/XMLSchema#string"
            >read</AttributeValue>
      </Apply>
    </Condition>
  </Rule>

</Policy>

```

All the rules are associated to a service ID (the value of the `fiware-service` header) and a subservice. When the request arrives to the Access Control, the later will retrieve all the permissions for the user roles, each one represented by a XACML policy. All the policies are applied then in order to find any that would let the request be executed.

In the example, the policy states the following: "if the resource has the prefix `frn:contextbroker:551:833:` and the action `read` the request would be allowed". This policy will allow read access over all the resources in subservice `833` of the service `551` to the roles that have it assigned. The meaning of the term resource will depend on the component which is being protected by the particular access rules. E.g.: for Orion Context Broker, the resources will be the entities of the CB; for each entity, the Policy Enforcement Point of the CB will generate a FRN, composed of the aforementioned prefix plus the identifier of the entity itself. 

Another example could be this the following:

```
<Policy xsi:schemaLocation="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17
    http://docs.oasis-open.org/xacml/3.0/xacml-core-v3-schema-wd-17.xsd"
        PolicyId="policy02"
        RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit"
        Version="1.0" xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">

  <Target>
    <AnyOf>
      <AllOf>
        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
          <AttributeValue
              DataType="http://www.w3.org/2001/XMLSchema#string">admin</AttributeValue>
          <AttributeDesignator
              AttributeId="urn:oasis:names:tc:xacml:1.0:subject:subject-id"
              DataType="http://www.w3.org/2001/XMLSchema#string"
              MustBePresent="false"
              Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject" />
        </Match>
        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-regexp-match">
          <AttributeValue
              DataType="http://www.w3.org/2001/XMLSchema#string">frn:contextbroker:551:833:.*</AttributeValue>
          <AttributeDesignator
              AttributeId="urn:oasis:names:tc:xacml:1.0:resource:resource-id"
              DataType="http://www.w3.org/2001/XMLSchema#string"
              MustBePresent="true"
              Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource" />
        </Match>
      </AllOf>
    </AnyOf>
  </Target>

  <Rule RuleId="policy02rule01" Effect="Permit">

    <Condition>
      <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
        <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-one-and-only">
          <AttributeDesignator
              AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id"
              DataType="http://www.w3.org/2001/XMLSchema#string"
              MustBePresent="true"
              Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action" />
        </Apply>
        <AttributeValue
            DataType="http://www.w3.org/2001/XMLSchema#string">write</AttributeValue>
      </Apply>
    </Condition>
  </Rule>

</Policy>

```

In this example, only those users with `subjectId` (user's role) "admin" may write on resources of tenant 511 and subservice 833.

Any number of policies can be included in the Access Control for each pair (tenant, subject). If any of the policies can be applied to the request and `Permit` the request, then the global result is a `Permit`. If none of the policies can be applied (no target exist for the tenant, subservice and subject of the request) the result will be `NotApplicable`. If there are policies that can be applied but all of them deny the access, the result will be a `Deny`.

## <a name="administration"/> Administration

#### Start service
To start the service, use either the service command:
service pepProxy start

Or just the launch script:
```
/etc/init.d/pepProxy start
```
For testing purposes it might be interesting to launch the process directly without the service. That can be done executing the following command from the project root directory:
```
./bin/pepProxy
```

Take into account that when the process is executed manually the system configuration for the script (in /etc/sysconfig/pepProxy) is not loaded and the default configuration (in /opt/pepProxy/config.js) is used. 

#### Stop service
To stop the service, use either the service command:
```
service pepProxy stop
```
Or just the launch script:
```
/etc/init.d/pepProxy stop
```
### How to check service status
#### Checking the process is running
The status of the process can be retrieved using the service command:
```
service pepProxy status
```
It also can be checked with ps, using a filter with the command name:
```
ps -ef | grep "bin/pepProxy"
```
In both cases a result of 0 (echoing $?) indicates the process is supposed to be running, and an error otherwise.
#### Checking that the port is listening
The following command:
```
netstat -ntpl | grep 1026
```
can be used to check the process is listening in the appropriate port (provided the port is the standard 1026). The result should resemble this line:
```
tcp   0   0  0.0.0.0:1026     0.0.0.0:*   LISTEN   12179/node
```
#### Checking the version in the Administration API
The PEP Proxy provides an Administration port that can be used to check whether the proxy is up and listening or down.
The administration API consists in a single `/version` path, that returns useful information from the proxy (currently just the listening port and version).

Example of output:
```
{
  "version": "0.4.1-next",
  "port": 1026
}
```

## <a name="configuration"/> Configuration
All the configuration of the proxy is stored in the `config.js` file in the root of the project folder. The values set inside config.js operate as the default values for all the important pieces of configuration data, so it is important none of them are removed (you can change them to suit your needs, as long as they have a valid value).

Another way of configuring the component is through the use of environment variables, although less configuration options are exposed with this mechanism.

### Basic Configuration
In order to have the proxy running, there are several basic pieces of information to fill:
* `config.resource.proxy`: The information of the server proxy itself. Two ports must be configured for the proxy: `port` indicates in which port is the proxy listening for requests; `adminPort` indicates the administration port. E.g.:
```
{
    port: 1026,
    adminPort: 11211
}
```
* `config.resource.original`: The address and port of the proxied server. E.g.:
```
{
    host: 'localhost',
    port: 10026
},
```
* `config.access`: connection information to the selected Access Control PDP API. Includes a `disable` flag, to allow the proxy to work in authentication-only mode and a flag to activate accounting access in file. E.g.:
```
{
    disable: false,
    protocol: 'http',
    host: 'localhost',
    port: 7070,
    path: '/pdp/v3',
    account: false,
    accountFile: '/tmp/pepAccount.log',
    accountMode: 'all'
}
```
Accounting log is only activated when account flag is true, and the logs are produced in a fixed INFO level for accessLogger, redardless of the pep log level.
Note that accounting log is not rotated, so you should make sure you configure your own rotation system.
Accounting access log include data about:
* Attempt was right or not
* Token
* Origin
* UserId
* UserName
* ServiceId
* Service
* SubServiceId
* SubService
* Action
* Path
* Body (Truncated to 100 chars when is valid access)
* Date
* Query
Example of access log:
```
"Right Attempt | ResponseStatus=200 | Token=gAAAAABnBPgPrgwpcAkbQOZIryu5ADUIScyorN3vbPYbTJxTE5AF3RO1y25Tf-sL3EKzvfr_1U3u8IL8ylB4e4B_vD5yZjc9rnrSIqoiC77B7uZ1O1xZCyukq_MkjRxJLqA9yQ5lQtAQCC6ig7Kn5uPhpPD-mhVb7kyQjUw1QjtCiyP7UKXZvKU | Origin=172.17.0.22 | UserId=753b954985bf460fabbd6953c71d50c7 | UserName=adm1 | ServiceId=9f710408f5944c3993db600810e97c83 | Service=smartcity | SubServiceId=/ | SubService=/ | Action=read | Path=/v2/entities | Query={\"limit\":\"15\",\"offset\":\"0\",\"options\":\"count\"} | Body={} | Date=2024-10-08T09:25:30.441Z"
```

Note that the above format is not the same than the regular PEP log (although it is also based in fields separated by `|`, the fields themselves are not the same).

Additionally a file configAccessMatch could be provided to pep to check matches about some elements involved in current access, regardless is right or not right access. For example:
* List for users involved
* List of headers and values
* List of subpaths in URL request
* List of subqueries in query request
* List of strings in body

PEP reloads this file each time it changes without needing restarting PEP itself.

This is an example of file `configAccessMatch.js` (full path `/opt/fiware-pep-steelskin/configAccessMatch.js` i.e. in a docker image):

```
// Activity related with a list of users
configAccessMatch.users = [
    'cracker1', 'cracker2',
];

// Activity related with request which the following headers
configAccessMatch.headers = [
    { "fiware-service": "smartcity" },
    { "x-real-ip": "127.0.0.1" }
];

// Activity related with request including the following subpaths
configAccessMatch.subpaths = [
    '/v1',
];

// Activity related with request including the following subqueries
configAccessMatch.subqueries = [
    'flowControl', 'options',
];

// Activity related with request including the following strings in body
configAccessMatch.body = [
    'legacy',
];
```

When any of theses patterns matches in current access, message access is added with `MATCHED <element> <value>` , where `<element>` would be: `USER`, `HEADER <header-name>`, `SUBPATH`, `SUBQUERY`, `BODY` and `<value>` the value which matches. For example:

```
Right Attempt MATCHED HEADER fiware-service smartcity | ResponseStatus=200 | Token=gAAAAABnBPgPrgwpcAkbQOZIryu5ADUIScyorN3vbPYbTJxTE5AF3RO1y25Tf-sL3EKzvfr_1U3u8IL8ylB4e4B_vD5yZjc9rnrSIqoiC77B7uZ1O1xZCyukq_MkjRxJLqA9yQ5lQtAQCC6ig7Kn5uPhpPD-mhVb7kyQjUw1QjtCiyP7UKXZvKU | Origin=172.17.0.22 | UserId=753b954985bf460fabbd6953c71d50c7 | UserName=adm1 | ServiceId=9f710408f5944c3993db600810e97c83 | Service=smartcity | SubServiceId=/ | SubService=/ | Action=read | Path=/v2/entities | Query={\"limit\":\"15\",\"offset\":\"0\",\"options\":\"count\"} | Body={} | Date=2024-10-08T09:25:30.441Z"
```
Account log has three modes: `all`, `matched`, `wrong`. First one `all` includes right and wrong access regardles if matches or not. Second one `matched` includes all wrong and just rigth matches acess. And `wrong` mode only includes all wrong access, regardless is matches or not with patterns.

* `config.componentName`: name of the component that will be used to compose the FRN that will identify the resource to be accessed. E.g.: `orion`.
* `config.resourceNamePrefix`: string prefix that will be used to compose the FRN that will identify the resource to be accessed. E.g.: `fiware:`.
* `config.bypass`: used to activate the administration bypass in the proxy. Valid values are `true` or `false`.
* `config.bypassRoleId`: ID of the role that will be considered to have administrative rights over the proxy (so being transparently proxied without validation). Valid values are Role UUIDs. E.g.: `db50362d5f264c8292bebdb5c5783741`.
* `config.dieOnRedirectError`: this flags changes the behavior of the PEP Proxy when an error is received when redirecting a request. If the flag is true, the PEP Proxy process is shut down immediately; if it is false, the behavior is the usual: generate a 501 Code error.
* `config.bodyLimit`: Controls the maximum request body size allowed, in bytes. Default is 1 Mb

### Authentication configuration
* `config.authentication.checkHeaders`: when the proxy is working with the access control disabled (just user authentication), indicates whether the `fiware-service` and `fiware-servicepath` headers should be checked for existance and validity (checking: the headers exist, thy are not empty and the user is really part of the service and subservice mentioned in the header). This option is ignored when authorization is enabled, and considered to be `true` (as the headers constitute a mandatory part of the authorization process). Default value is `true`.
* `config.authentication.module`: indicates what type of authentication server should be used: keystone or idm. The currently supported one (and default) is `keystone`.
* `config.authentication.username`: username of the PEP proxy in the IDM. 
* `config.authentication.password`: password of the PEP proxy in the IDM.
* `config.authentication.domainName`: (only meaningful for Keystone) name of the administration domain the PEP proxy user belongs to.
* `config.authentication.retries`: as the authentication is based in the use of tokens that can expire, the operations against Keystone are meant to retry with a fresh token. This configuration value indicates how many retries the PEP should perform in case the communication against Keystone fails. The value `0` means the default will be used (default value is 3). The value `-1` implies that it should be retried forever.
* `cacheTTLs`: the values in this object correspond to the Time To Live of the values of the different caches the PEP uses to cache requests for information in Keystone. The value is expressed in seconds and `0` value implies unlimited.
* `config.authentication.options`: address, port and other communication data needed to communicate with the Identity Manager. Apart from the host and port, default values should be used. 

### Plugin configuration
The `config.js` file contains configuration parameter that lets the deployer decide what plugin the proxy should use in order to extract the action type from the request attributes: the `middleware` parameter. This object has two attributes:
* `require`: indicating the route from the project folder to the module that contains the middleware.
* `functions`: an array of the middlewares to execute from the selected module.
All the currently available plugins are in the folder `lib/plugins/`, and most of them implement a single middleware called `extractAction` (the name for Orion plugin is `extractCBAction`).
The following example should work for any plugin following this patterns:
```
config.middlewares = {
    require: 'lib/plugins/perseoPlugin',

    functions: [
        'extractAction'
    ]
};
```
The environment variables provide ways of configuring the plugin without taking care of this details.

### Configuration based on environment variables
Some of the configuration values for the attributes above mentioned can be overriden with values in environment variables. The following table shows the environment variables and what attribute they map to.

| Environment variable | Configuration attribute             |
|:-------------------- |:----------------------------------- |
| PROXY_PORT           | config.resource.proxy.port          | 
| ADMIN_PORT           | config.resource.proxy.adminPort     | 
| TARGET_HOST          | config.resource.original.host       |
| TARGET_PORT          | config.resource.original.port       |
| LOG_LEVEL            | config.logLevel                     |
| ACCESS_DISABLE       | config.access.disable               |
| ACCESS_HOST          | config.access.host                  |
| ACCESS_PORT          | config.access.port                  |
| ACCESS_PROTOCOL      | config.access.protocol              |
| ACCESS_ACCOUNT       | config.access.account               |
| ACCESS_ACCOUNTFILE   | config.access.accountFile           |
| ACCESS_ACCOUNTMODE   | config.access.accountMode           |
| AUTHENTICATION_HOST  | config.authentication.options.host  |
| AUTHENTICATION_PORT  | config.authentication.options.port  |
| AUTHENTICATION_PROTOCOL  | config.authentication.options.protocol  |
| AUTHENTICATION_CACHE_PROJECTIDS  | config.authentication.cacheTTLs.projectIds  |
| AUTHENTICATION_CACHE_ROLES  | config.authentication.cacheTTLs.roles  |
| AUTHENTICATION_CACHE_USERS  | config.authentication.cacheTTLs.users  |
| AUTHENTICATION_CACHE_VALIDATION | config.authentication.cacheTTLs.validation  |
| PROXY_USERNAME       | config.authentication.user          |
| PROXY_PASSWORD       | config.authentication.password      |
| PROXY_PASSWORD       | config.authentication.password      |
| COMPONENT_NAME       | config.componentName                |
| COMPONENT_PLUGIN     | config.middlewares and config.componentName if no COMPONENT_NAME provided     |
| BODY_LIMIT           | config.bodyLimit                        |

### Component configuration
A special environment variable, called `COMPONENT_PLUGIN` can be set with one of this values: `orion`, `perseo`, `keypass` and `rest`. This variable can be used to select what component plugin to load in order to determine the action of the incoming requests. This variable also rewrites `config.componentName` configuration paramenter.

### SSL Configuration
If SSL Termination is not available, the PEP Proxy can be configured to listen HTTPS instead of plain HTTP. To activate the SSL:

* Create the appropiate public keys and certificates and store them in the PEP Proxy machine.
* In the `config.js` file, change the `config.ssl.active` flag to true.
* In the same ssl object in the configuration, fill the path to the key and cert files.

### Multi-instance configuration
PEP Proxy is able to start multiple instances by adding and configuring certain files in `/etc/pepProxy.d` and using `pepProxy` service script

In order to start multiple instances of the proxy, just add one configuration file per instance in the `/etc/pepProxy.d` folder.

In its starting sequence, the `pepProxy` service looks for files in  `/etc/pepProxy.d` that begins with `pepproxy_` prefix and has `.conf` extension and start (or stop or status or restat) one process for file found.

It is important to change `PROXY_PORT` and `ADMIN_PORT` to one not used by other PEP intances/services. 

## <a name="apiaccesscontrol"/> API With Access Control
The validation of each request si done connecting with the Access Control component, which, using the information provided by the PEP Proxy, decides whether the user can execute the selected action in this organization or not. The following is a summary of this interaction with some examples.


### Request
The XACML Request maps the information extracted from the request and from the IDM (roles, organization and action) to XACML categories (`access-subject`, `resource` and `action`, respectively). 
```
<?xml version="1.0" encoding="UTF-8"?>
<Request xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17 http://docs.oasis-open.org/xacml/3.0/xacml-core-v3-schema-wd-17.xsd"
         ReturnPolicyIdList="false">
    <!-- X-Auth-Token-->
    <Attributes Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject">
        <Attribute IncludeInResult="false"
                   AttributeId="urn:oasis:names:tc:xacml:1.0:subject:subject-id">
            <AttributeValue
                    DataType="http://www.w3.org/2001/XMLSchema#int">511</AttributeValue>
        </Attribute>
    </Attributes>
    <!-- fiware resource name being accessed: organization id -->
    <Attributes
            Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource">
        <Attribute IncludeInResult="false"
                   AttributeId="urn:oasis:names:tc:xacml:1.0:resource:resource-id">
            <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">frn:contextbroker:551:::</AttributeValue>
        </Attribute>
    </Attributes>
    <!-- action performed -->
    <Attributes
            Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action">
        <Attribute IncludeInResult="false"
                   AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id">
            <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">create</AttributeValue>
        </Attribute>
    </Attributes>
</Request>
```

### Response
The XACML Response returns a `Decision` element that can have the following values: “Permit”, “Deny”, “NotApplicable” or “Indeterminate”. The subset of allowable values understood by the PEP Proxy is:
* `Permit`: allows the request to continue its way to the Context Broker.
* `Deny`: rejects the request, returning a 403 error to the requestor.


```
<?xml version="1.0" encoding="UTF-8"?>
<Response xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17 http://docs.oasis-open.org/xacml/3.0/xacml-core-v3-schema-wd-17.xsd">
    <Result>
        <Decision>Permit</Decision>
    </Result>
</Response>
```
## <a name="rules"/> Rules to determine the Context Broker action from the request

### Available actions

This is the list of actions available for the Context Broker. For every action, the abbreviature is also shown (will be used in some of the following tables). 

| Action | Abbreviature |
| ------ |:------------:|
| create | C            |
| update | U            |
| delete | D            |
| read | R            |
| subscribe | S            |
| register | Reg           |
| discover | Dis            |
| N/A | - |

#### NGSIv2
| Method | Path                                                                                    | Action |
| ------ |:--------------------------------------------------------------------------------------- | ---:|
| GET    | /v2                                                                                     | R |
| GET    | /v2/entities                                                                            | R |
| GET    | /v2/entities/{entityId}                                                                | R |
| GET    | /v2/entities/{entityId}/attrs                                                          | R |
| POST   | /v2/entities                                                                           | C |
| PATCH  | /v2/entities/{entityId}/attrs                                                          | U |
| POST   | /v2/entities/{entityId}/attrs                                                          | U |
| POST   | /v2/entities/{entityId}/attrs?options=append                                           | C |
| DELETE | /v2/entities/{entityId}                                                                | D |
| PUT    | /v2/entities/{entityId}/attrs                                                          | U |
| GET    | /v2/entities/{entityId}/attrs/{attrId}                                                 | R |
| PUT    | /v2/entities/{entityId}/attrs/{attrId}                                                 | U |
| DELETE | /v2/entities/{entityId}/attrs/{attrId}                                                 | D |
| GET    | /v2/entities/{entityId}/attrs/{attrId}/value                                           | R |
| PUT    | /v2/entities/{entityId}/attrs/{attrId}/value                                           | U |
| GET    | /v2/types                                                                              | R |
| GET    | /v2/types/{typeId}                                                                     | R |
| GET    | /v2/subscriptions                                                                      | R |
| POST   | /v2/subscriptions                                                                      | C |
| GET    | /v2/subscriptions/{subscriptionId}                                                     | R |
| PATCH  | /v2/subscriptions/{subscriptionId}                                                     | U |
| DELETE | /v2/subscriptions/{subscriptionId}                                                     | D |
| POST   | /v2/op/query                                                                           | R |
| POST   | /v2/op/update                                                                          | (*) |

(*) It depends on the `actionType` (within payload):

* update: U
* append: C
* appendStrict: C
* delete: D
* replace: U

Operations marked with a slash, "-" are now deprecated. All those operations will be tagged with the special action "N/A". If you want to allow them anyway, just add a rule to the Access Control allowing the "N/A" action for the desired roles.

## <a name="rulesPerseo"/> Rules to determine the Perseo CEP action from the request

The available actions are:
* **readRule**: to get working rules in CEP
* **writeRule**: to modify rules in CEP (create, delete, update)
* **notify**: to fire rules (if appropiate) with an event notification

The following tables show the map from method and path of the request to the action. 

### Notifications
| Method | Path |  Action |
| ------ |:-----|:------------|
| POST   | /notices | notify|

### Rules
| Method | Path        | Action| 
| ------ |:-------------|:-----------|
| GET    | /rules      | readRule  |
| GET    | /rules/{id} | readRule  |
| POST   | /rules      | writeRule |
| DELETE | /rules/{id} | writeRule |

### Visual Rules
| Method | Path    |  Action |
| ------ |:--------|:------------|
| GET    | /m2m/vrules          | readRule |
| GET    | /m2m/vrules/{id}       | readRule |
| POST   | /m2m/vrules          | writeRule |
| DELETE | /m2m/vrules/{id}     | writeRule |
| PUT    | /m2m/vrules/{id}       | writeRule |

## <a name="rulesKeypass"/> Rules to determine the Keypass Access Control action from the request
The available actions are:
* **createPolicy**: to create a new policy for a subject in Keypass.
* **listPolicies**: to list all the policies belonging to a subject.
* **deleteSubjectPolicies**: to remove all the policies for a particular subject.
* **deleteTenantPolicies**: to remove all the policies for all the subjects of a tenant.
* **readPolicy**: to get the policy body for a particular policy.
* **deletePolicy**: to remove a single policy of a subject.

The following table show the map from method and path of the request to the action.

| Method | Path        | Action|
| ------ |:-------------|:-----------|
| POST    | /pap/v1/subject/{subjectId}      | createPolicy  |
| GET    | /pap/v1/subject/{subjectId}       | listPolicies  |
| DELETE    | /pap/v1/subject/{subjectId}       | deleteSubjectPolicies  |
| DELETE    | /pap/v1      | deleteTenantPolicies  |
| GET    | /pap/v1/subject/{subjectId}/policy/{policyId}      | readPolicy  |
| DELETE    | /pap/v1/subject/{subjectId}/policy/{policyId}      | deletePolicy  |

## <a name="customizing"/> Customizing PEP Proxy for other components
Most of the code of the proxy (i.e. the extraction of user data, the communication with the Keystone Proxy and the proxy process itself) will execute exactly the same for all the components. The exception is the rule to determine the action the request is trying to perform. To address this behavior and possible actions different customizations of the proxy could need, the proxy allows for the introduction of middlewares in the validation process.

### Middleware definition
The middlewares are quite similar to the ones used by the Connect (or Express) framework. A middleware is a function that receives three parameters:

* req: The object representing the incoming HTTP request. Along with all the request information, the request is used to store the information for the validation process (i.e. attributes `userId` with the user token, `organization` with the organization extracted from the headers and `action` that should be filled in by the middlewares).
* res: The object representing the response. This object can be used to stop the request pipeline due to conditions defined by the specific component (although it is advisable to use a `next(error)` call with a custom error to allow the error to be handled by the proxy).
* next: Callback used to call the next middleware in the chain. In the current version, it is required that the call to the next middleware contains both the request and response objects (this behavior is not the same as the one in Connect middlewares). If the first parameter in the call is an error, the request will be rejected. If the first parameter is null or undefined, the request will continue through the validation process. This is an example of a call to next that lets the request follow through:

```
next(null, req, res);
```

### Middleware configuration
The middlewares must be defined inside a Node.js module. They can be configured using the `config.middlewares` object of the `config.js` file. This object contains two attributes:

* `require`: path to the module that contains the middlewares, from the project root. The system currently supports only modules defined inside the fiware-pep-steelskin project (or in accessible folders).
* `functions`: list of the middlewares to load. The names in this list must be exported functions of the module selected in the previous attribute.

### Generic REST Middleware
For standard REST APIs that make use exclusively of the POST, PUT, DELETE and GET methods with their CRUD meaning, the PEP Proxy provides a generic plugin that maps those methods to actions in the access request. To configure it, put the following lines in the middleware section of the PEP Proxy installation:

```
config.middlewares = {
   require: 'lib/services/restPlugin',
   
   functions: [
     'extractAction'
   ]
};
```
In order to add more expression power to the authorization rules created in the Access Control component, the Generic REST Plugin adds a new element to the FRN: the URL of the resource is appended to the existing elements in the FRN.

### URL Table Generic middleware
For applications that require a mapping between URLs and Method to actions when the REST Middleware is not enough, a plugin generator based on tables is provided. In order to use this plugin, create a new plugin file and import the `./urlTablePlugin` module. This module contains just one function, `extractAction`, that takes a mapping table and generates a middleware function that extract the action of a request based on it. 

The mapping table has to have one row for each action to check indicating:
* Request **Method**
* **URL** pattern (using regular expressions)
* **Action** name
Whenever a request arrives to the plugin with the selected method and a URL that matches the URL expression, the action will be assigned to the request.

An example of use of the `urlTablePlugin` can be found in the Perseo plugin.

## <a name="licence"/> License

Orion FiWare Policy Enforcement Point is licensed under Affero General Public License (GPL) version 3.

## <a name="development"/> Development documentation
### Project build
The project is managed using npm.

For a list of available task, type
```bash
npm run
```

The following sections show the available options in detail.

### Testing
[Mocha](http://visionmedia.github.io/mocha/) Test Runner + [Should.js](https://shouldjs.github.io/) Assertion Library.

The test environment is preconfigured to run BDD testing style.

Module mocking during testing can be done with [proxyquire](https://github.com/thlorenz/proxyquire)

To run tests, type

```bash
npm test
```

### Coding guidelines
jshint

Uses provided .jshintrc flag file.
To check source code style, type

```bash
npm run lint
```

### Continuous testing

Support for continuous testing by modifying a src file or a test.
For continuous testing, type

```bash
npm run test:watch
```

If you want to continuously check also source code style, use instead:

```bash
npm run watch
```

### Code Coverage
Istanbul

Analizes the code coverage of your tests.

To generate an HTML coverage report under `site/coverage/` and to print out a summary, type

```bash
# Use git-bash on Windows
npm run test:coverage
```

### Clean

Removes `node_modules` and `coverage` folders, and  `package-lock.json` file so that a fresh copy of the project is restored.

```bash
# Use git-bash on Windows
npm run clean
```

### Releasing
The project contains a script to aid in the releasing process. This script is located in the `scripts/build` folder. In
order to create a new release, just invoke the script, from the project root folder, with the following line:
```
scripts/build/release.sh <NEW_VERSION> <RELEASE_TYPE>
```
Usually, `RELEASE_TYPE` will be `sprint`. This release procedure will do the following steps:
* Change the version in package.json to the selected version.
* Create a branch `release/0.6.0` and a tag `0.6.0` from `master`.
* Add the `-next` suffix to the version in master and clean the `CHANGES_NEXT_RELEASE` file.

For other release types, check the command help.
