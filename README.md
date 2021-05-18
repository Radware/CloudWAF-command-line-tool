# cwafctl

cwafctl is a commandline utility that allows to manage cloud waf objects from the client. It allows to perform several actions from the cli, such as retrieving objects such as certificates, application configuration, etc. In addition, it allows to update and modify existing protections within a given cloud waf account. The first step before using cwafctl is to update the file settings.py to include api credentials that must be created in your Radware Cloud WAF account prior to using this tool.

cwafctl works with yaml, it allows you to retrieve information in yaml format, that you can save to a file, modify and later on re-use to update the object.

cwafctl requires python 3.8 to run.


# How to use
cwafctl basically implements the 3  commands below:
 * **get** :    Allows to retrieve a configuration
 * **create**:  Allows to deploy new configurations (ex.:new applicaition,certificate,etc.)
 * **delete**:  Allows to delete an object
 * **set**:     Allows to modify an existing configuration

## Retrieving objects using the "get" command
In order to list applications currently onboarded on your cloud waf account and dump it to a yaml file:

  **python cwafctl.py get applications > applications.yaml**


In order to list certificates deployed in your account and dump it to a yaml file:

 **python cwafctl.py get certificates > certificates.yaml**


In order to get a specific application configuration and dump it to a yaml file:

 **python cwafctl.py get application "HacmeBank" > hacmebankapp.yaml**


To get the full list of available commands and objects that are retrievable:

 **python cwafctl.py get --help"**

## Deploying objects using the "create" command
In order to deploy an application:
  **python cwafctl.py create application < newapp.yaml** [see yaml folder for an example of a yaml file used to onboard an application]

In order to deploy a certificate:
  **python cwafctl.py create certificate < certificate.yaml** [see the yaml folder for an example of how to onboard a certificate]

## Deleting objects using the "delete" command
In order to delete a certificate:
   **python cwafctl.py delete certificate FINGERPRINT**
 where FINGERPRINT can be obtained by listing the certificates using the command **python cwafctl.py get certificates"

 ## Modifying existing configuration using the "set" command




