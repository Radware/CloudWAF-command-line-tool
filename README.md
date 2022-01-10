# cwafctl

**cwafctl** is a command-line utility that interfaces with Radware Cloud WAF over REST API. It allows to manage Cloud WAF from the CLI.

**cwafctl** works with yaml, it allows you to retrieve information in yaml format, that you can save to a file, modify and later on re-use to update the object. The yaml objects used by cwafctl are mapped directly to the JSON format supported by Cloud WAF for API calls.

**cwafctl** requires **python 3.8** to run and was tested using windows 10.

# How to install
You can use the python package installer "pip" to deploy cwafctl:

    pip install cwafctl

In order to configure your user name and password, please use the following command initially:

    cwafctl utils setUserNameAndPassword --username="username@domain.com" --password="password"

where username and password are Radware Cloud WAF API credentials. It will store those credentials in the user home folder. <br><br>

For instructions on how to create an API user in Cloud WAF, please consult https://portals.radware.com/ProductDocumentation/Cloud_WAF_API_User_Guide/index.html#page/Cloud%20WAF%20API%20User%20Guide/Cloud%20WAF%20API%20Users%20Guide%20v6_AB.1.09.html


# How to use
cwafctl basically implements the commands below:
 * **get** :    Allows to retrieve a configuration
 * **create**:  Allows to deploy new configurations (ex.:new application,certificate,etc.)
 * **delete**:  Allows to delete an object
 * **set**:     Allows to modify an existing configuration
 * **utils**:   Misc utilities

## Retrieving objects using the "get" command

cwafctl currently allows to retrieve the following objects from Radware Cloud WAF:

| Object        | Description                                      |
| :--------------| :------------------------------------------------ |
| activity_logs  | Gets the activity logs in YAML                   |
| application    | Gets an application configuration by name in YAML|
| application_access_rules | Gets the application's access rules settings in YAML |
| application_acl | Gets an application ACL by name in YAML  |
| application_dns_records |                    Gets the application's dns diversion records in YAML|
| application_domain |                          Gets an application's main domain name in YAML|
| application_generalinfo  |                   Gets an application's general info by name in YAML|
| application_network_configuration |          Gets an application's  service settings such as services, certificate and health checks|
| application_ip_persistency     |             Gets the application's persistency settings in YAML|
| application_origin_servers      |            Gets the application's origin servers settings in YAML|
| application_protection_allowed_urls     |    Gets the application's allowed URLs protection settings in YAML|
| application_protection_anonymous_proxy   |   Gets the application's Anonymous proxy blocking protection settings in YAML|
| application_protection_anti_bot        |     Gets the application's anti-bot protection settings in YAML|
| application_protection_api              |    Gets the application's API protection settings in YAML|
| application_protection_database         |    Gets the application's database protection settings in YAML|
| application_protection_ddos               |  Gets the application's ddos protection settings in YAML|
| application_protection_ert_attackers_feed  | Gets the application's ert attackers feed settings in YAML|
| application_protection_http_compliance  |    Gets the application's HTTP compliance protection settings in YAML|
| application_protection_vulnerabilities    |  Gets the application's vulnerability protection settings in YAML|
| application_protocol_security             |  Gets an application protocol security info (ex.:TLS settings) in YAML|
| application_protocols_and_health_checks   |  Gets an application protocol and health checks in YAML|
| application_security_bypass             |    Gets the application's security bypass settings in YAML|
| application_security_page              |     Gets the application's blocking page settings in YAML|
| application_true_client_ip            |      Gets the application's true client ip settings in YAML|
| application_certificate_fingerprint   |      Gets an application's associated certificate fingerprint |
| application_v2                        |      Gets an application v2 configuration by name in YAML|
| applications                          |      Gets the current list of applications in YAML format|
| available_regions                    |       Gets a list of the available regions for this customer account. Useful to get the right region codes before deploying an app.|
| bad_bots                             |       Gets the list of observed bad bots for the application name provided|
| certificates                        |        Gets the list of certificates deployed in CWAF in YAML format|
| customer_info                       |        Gets the customer information for the current account.|
| events_ddos                         |        Retrieves DDoS events from Cloud WAF|
| events_waf                         |         Retrieves WAF events from Cloud WAF|
| legitimate_bots                    |         Gets the list of observed legitimate bots for the application name provided|
| policy_distribution                 |        Get policy distribution settings in YAML|
| search_engine_bots                  |        Gets the list of search engine bots observed for the application name provided|
| templates_geo_blocking             |         Gets geoblocking policies templates in YAML|
| templates_ip_groups                |         Get IP group templates in YAML|
| templates_security_policies        |         Get security policies templates in YAML|
| user                               |         Gets a specific user information by first name and last name|
| users                             |          Gets a list of users in Cloud WAF|

<br><br>

In order to list applications currently onboarded on your cloud waf account and retrieve the information in yaml format:

    cwafctl get applications

This an example of the CLI output:


        applications:
        - accountId: 607b9775-a04a-4efa-ba97-228909abc300
          accountName: US Region PoCs
          applicationId: 9d8213f6-580f-406c-9bda-618ef9b3896d
          applicationName: Juice Shop
          creationDate: 1617758940383
          customDeployment: false
          deploymentStatus: PROTECTING
          frontend: alcon
          mainDomain: juice-shop.herokuapp.com
          region: North America (Ashburn)
        - accountId: 607b9775-a04a-4efa-ba97-228909abc300
          accountName: US Region PoCs
          applicationId: db3718bc-de94-40c1-9adf-300a41069e44
          applicationName: rs_hackazon
          creationDate: 1598545097301
          customDeployment: false
          deploymentStatus: PROTECTING
          frontend: alcon
          mainDomain: rsamazon.ddns.net
          region: North America (Ashburn)
        ....
        numberOfElements: 7
        page: 0
        totalElements: 7
        totalPages: 1

You can dump the content directly to a yaml file by using the following syntax:<br>

    cwafctl get applications > applications.yaml


In order to list certificates deployed in your account and dump it to a yaml file:

    cwafctl get certificates > certificates.yaml


In order to get a specific application configuration and dump it to a yaml file:

    cwafctl get application "HacmeBank" > hacmebankapp.yaml


To get the full list of available commands and objects that are retrievable:

    cwafctl get --help


 To get help on a specific command, you can use the following syntax:

    cwafctl get application --help

 CLI Output:

    python cwafctl get application --help
    INFO: Showing help with the command 'cwafctl get application -- --help'.

    NAME
        cwafctl get application - Gets an application configuration by name in YAML

    SYNOPSIS
        cwafctl get application NAME

    DESCRIPTION
        Gets an application configuration by name in YAML

    POSITIONAL ARGUMENTS
        NAME

    NOTES
        You can also use flags syntax for POSITIONAL ARGUMENTS



## Deploying a new application in Cloud WAF using cwafctl and the create command


cwafctl currently allows to create (deploy) the following objects:

| Object        | Description                                           |
| :--------------| :------------------------------------------------    |
| application    | Deploys an application using a configuration stored in a yaml file ex.: cwafctl create application < newapp.yaml . See the /yaml files/newapp.yaml for an example.|
| certificate    | Deploys an certificate using a configuration stored in a yaml file. ex.: cwafctl.py create certificate < certificate.yaml . See the /yaml files/certificate.yaml for an example. |                                                     |

<br><br>


**To deploy the certificate:**

    cwafctl create certificate < ./"yaml files"/certificate.yaml

**To deploy the application:**

    cwafctl create application < ./"yaml files"/newapp.yaml


The "yaml files" folder contains yaml files that are usable to deploy a certificate specified in the certificate.yaml file along with a newapp.yaml file that specifies where to deploy the app. Those files can be edited and updated to match with your applications required deployment parameters.


**newapp.yaml** file content:


        applicationName: My application
        mainDomain: www.test.com
        protocol: BOTH
        region: CANADA_1
        originServers:
        - address: 2.2.2.2
          addressType: IP
        - address: 3.3.3.3
          addressType: IP
        generalInfo:
          ownerName: Christian Shink
          ownerEmail: christian.shink@test.com
          externalID: '123445'
          description: test
        fingerprint: 87FE361698CB3F47683245984DDAF08E334818D3


Please note that the sha1 "fingerprint" field above can be calculated before the deployment using the following command:

    cwafctl utils get_certificate_fingerprint < ./"yaml files"/certificate.yaml

Please note that the available region codes can be obtained from cloud waf using the following commands:

    cwafctl get available_regions

CLI output:

    - CANADA_1
    - US_EAST_1
    - US_CENTRAL_1


Please note that the "certificate.yaml" file can either be created manually using the same format as in ./"yaml files"/certificate.yaml or be generated using the following command:

    cwafctl utils generate_yaml_cert_file certificate.pem key.pem certchain.pem test > certificate.yaml

* where certificate.pem is the file containing the public key<br>
* where key.pem is the file containing the private key<br>
* where certchain.pem is the file containing the certificate chain<br>
* where test is the passphrase that was used to encrypt the certificate<br>


## Modifying existing configuration using the "set" command

The following objects can be updated in Radware Cloud WAF using cwafctl **set** command:

| Object                                    |  Description |
|:---------                                 |:---------
|application_access_rules                   | Updates an application's access rules settings section via YAML|
|application_domain                         | Updates an application's domain name section via YAML|
|application_generalinfo                    | Updates an application's general information section via YAML|
|application_network_configuration          | Updates an application's network configuration, including services (HTTP,HTTPS), certificate and health checks via YAML|
|application_ip_persistency                 | Updates an application's ip persistency settings section via YAML|
|application_origin_servers                 | Updates an application's origin server settings section via YAML|
|application_protection_allowed_urls        | Updates an application's allowed urls protection section via YAML|
|application_protection_anonymous_proxy     | Updates an application's anonymous proxy protection section via YAML|
|application_protection_database            | Updates an application's database protection section via YAML|
|application_protection_vulnerabilities     | Updates an application's vulnerabilities protection section via YAML|
|application_protocol_security              | Updates an application' protocols security configuration  section via YAML|
|application_protocols_and_health_checks    | Updates an application protocol and health checks in YAML|
|application_security_bypass                | Updates an application's security bypass settings section via YAML|
|application_security_page                  | Updates an application's security page via YAML|
|application_true_client_ip                 | Updates an application' True Client IP settings section via YAML|
|application_certificate_by_fingerprint     | Updates the certificate in use by an application using a certificate fingerprint of an already uploaded certificate.|
<br><br>

Any "get" command for the corresponding objects can be used to retrieve an object that can be stored and edited locally and later pushed using the "set" command.

 For example:

The following commands retrieve the "general information section of an application" and wil store it to a yaml file

    cwafctl get application_generalinfo "HacmeBank" > generalInfo.yaml

The content of the yaml file is the following:

    description: null
    externalID: null
    ownerEmail: null
    ownerName: Christian Shink

The field "description" can be modified and edited  and the content becomes the folowing :

    description: HacmeBank application
    externalID: null
    ownerEmail: null
    ownerName: Christian Shink

once the field has been edited, the new General Info for the application "HacmeBank" can be set using the following command:

    cwafctl set application_generalinfo "HacmeBank" < generalInfo.yaml



## Deleting objects using the "delete" command

cwafctl currently supports deleting applications and certificates from Radware Cloud WAF. The 2 examples below illustrate how to use the commands.

**To delete a certificate:**

    cwafctl delete certificate FINGERPRINT

where **FINGERPRINT** is the SHA1 fingerprint of the public key. Certificate fingerprints can be extracted from Cloud WAF using the command: **cwafctl get certificates**"
<br><br><br>
**To delete an application:**

    cwafctl delete application APPNAME

where **APPNAME** is the application name.


## Retrieving security events from Radware Cloud WAF
<br>
You can retrieve waf events from Cloud WAF by using the following command:

    cwafctl get events_waf

It will retrieve the top 10000 events ordered by date. You can in addition scope the search to a specific source IP or protected application by using the --sourceIP and --applicationName parameters.
<br><br><br><br>
You can retrieve ddos events from Radware Cloud WAF using the following command:

    cwafctl get events_ddos

It will retrieve the top 10000 events ordered by date. You can in addition scope the search to a specific source IP or destination IP or application by using the flags --sourceIP, --destinationIP and --applicationName.
<br><br><br><br>

For customers using the Radware BOT manager integrated in Cloud WAF. You can retrieve the current list of bad bots using the following command:

    cwafctl get bad_bots "appName"

where "appName" is the name of the application protected by Cloud WAF.
<br><br><br><br>

For customers using the Radware BOT manager integrated in Cloud WAF. You can retrieve the list of legitimate bots using the following command:

    cwafctl get legitimate_bots "appName"

where "appName" is the name of the application protected by Cloud WAF.
<br><br><br><br>

For customers using the Radware BOT manager integrated in Cloud WAF. You can retrieve the list of search engines using the following command:

    cwafctl get search_engine_bots "appName"

where "appName" is the name of the application protected by Cloud WAF.
<br><br><br><br>

## Renewing a certificate for an application deployed in Cloud WAF
<br>
cwafctl includes a utility that allows to easily upload a new certificate to Cloud WAF and to delete the old one :

    cwafctl utils updateCertificate --publicKeyFilePath='certificate2.pem' --privateKeyFilePath='key2.pem' --certChainFilePath="chain.pem" --appName='TestDotCom' --passphrase='pass'

where **publicKeyFilePath** is  the path to a pem file containing the certificate.<br>
where **privateKeyFilePath** is the path to a pem file containing the key.<br>
where **certChainFilePath** is the path to a pem file containing the certificate chain.<br>
where **passphrase** is the passphrase used to encrypt the key.<br>
where **appName** is the application name as deployed in Cloud WAF.<br><br>
**certChainFilePath** and **passphrase** are optional parameters.<br>
















