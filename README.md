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


## Deploying objects using the "create" command
In order to deploy an application:

    cwafctl create application < newapp.yaml  [see yaml folder for an example of a yaml file used to onboard an application]

In order to deploy a certificate:

    cwafctl create certificate < certificate.yaml  [see the yaml folder for an example of how to onboard a certificate]

## Deleting objects using the "delete" command

**To delete a certificate:**

    cwafctl delete certificate FINGERPRINT

where **FINGERPRINT** is the SHA1 fingerprint of the public key. Certificate fingerprints can be extracted from Cloud WAF using the command: **cwafctl get certificates**"
<br><br><br>
**To delete an application:**

    cwafctl delete application APPNAME

where **APPNAME** is the application name.


## Modifying existing configuration using the "get" and "set" command

Any "get" command can be used to retrieve an object that can be stored and edited locally and later pushed using the "set" command.

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


## Deploying a new application using cwafctl

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


## Retrieving security events from Radware Cloud WAF
<br><br>
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














