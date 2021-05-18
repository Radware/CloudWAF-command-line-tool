# cwafctl

cwafctl is a commandline utility that allows to manage cloud waf objects from the client. It allows to perform several actions from the cli, such as retrieving objects such as certificates, application configuration, etc. In addition, it allows to update and modify existing protections within a given cloud waf account. The first step before using cwafctl is to update the file settings.py to include api credentials that must be created in your Radware Cloud WAF account prior to using this tool.

cwafctl works with yaml, it allows you to retrieve information in yaml format, that you can save to a file, modify and later on re-use to update the object. The yaml objects used by cwafctl are mapped directly to the JSON format supported by Cloud WAF for API calls.

cwafctl requires python 3.8 to run and was tested using windows 10.


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


 To get help on a specific command, you can use the following syntax:

 **python cwafctl.py get application --help**

 CLI Output:

    python cwafctl.py get application --help
    INFO: Showing help with the command 'cwafctl.py get application -- --help'.

    NAME
        cwafctl.py get application - Gets an application configuration by name in YAML

    SYNOPSIS
        cwafctl.py get application NAME

    DESCRIPTION
        Gets an application configuration by name in YAML

    POSITIONAL ARGUMENTS
        NAME

    NOTES
        You can also use flags syntax for POSITIONAL ARGUMENTS


## Deploying objects using the "create" command
In order to deploy an application:
  **python cwafctl.py create application < newapp.yaml** [see yaml folder for an example of a yaml file used to onboard an application]

In order to deploy a certificate:
  **python cwafctl.py create certificate < certificate.yaml** [see the yaml folder for an example of how to onboard a certificate]

## Deleting objects using the "delete" command
To delete a certificate:
   **python cwafctl.py delete certificate FINGERPRINT**

where **FINGERPRINT** can be obtained by listing the certificates using the command **python cwafctl.py get certificates"

To delete an application:
    **python cwafctl.py delete application APPNAME

where **APPNAME** is the application name.


## Modifying existing configuration using the "get" and "set" command

Any "get" command can be used to retrieve an object that can be stored and edited locally and later pushed using the "set" command.

 For example:

    The following commands retrieve the "general information section of an application" and wil store it to a yaml file

    python cwafctl.py get application_generalinfo "HacmeBank" > generalInfo.yaml

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
    **python cwafctl.py set application_generalinfo "HacmeBank" < generalInfo.yaml


## Deploying a new application using cwafctl

The "yaml files" folder contains yaml files that are usable to deploy a certificate specified in the certificate.yaml file along with a newapp.yaml file that specifies where to deploy the app.
In order to get the regions code for the available regions that you can deploy in, you can use the following files:

newapp.yaml file content:


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

Please note that the "fingerprint" field here can be calculated using the following command:
python cwafctl.py utils get_certificate_fingerprint < ./"yaml files"/certificate.yaml

Please note that the available region codes can be obtained from cloud waf using the following commands:
**python cwafctl.py get available_regions**
CLI output:
    python cwafctl.py get available_regions
    - CANADA_1
    - US_EAST_1
    - US_CENTRAL_1


cert.yaml file content:
        certificate: |-
         -----BEGIN CERTIFICATE-----
         MIICzDCCAbSgAwIBAgIJAOg5uU72jLpRMA0GCSqGSIb3DQEBBQUAMBcxFTATBgNV
         BAMTDHd3dy50ZXN0LmNvbTAeFw0yMTA1MDMwODI3MTZaFw0zMTA1MDEwODI3MTZa
         MBcxFTATBgNVBAMTDHd3dy50ZXN0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEP
         ADCCAQoCggEBAKMB23DlAYI5sX5AumYVr1k1GF4ASLmC2kbJfKi6Qq7pLN7qZiz6
         IA/VhWrCr6GOBEPSG93ICxW/D2x/3B4MyEmFu9cSkeht+5RoJjFX43uEGnVMWC+o
         j2sr62sBXz68O+XRzeVAxWBnJj4rstj+1RgZulYn+/6dTyvkfLuWBM0GJlTtxGf6
         Y09xGWXwxyTmiHIcNsn1BkRRDcXMr0mZogK+UWdqMXVq6dRuQN315r4HdEZ8xlCM
         eWC9EufIbtl1tm3mjSEQ1jhZWeIAKrpdIMytAdtoymDHUgfkcQWo1iTvnYcQ4OVf
         0wlCmIJUJLw9WjOKSsJW06us6Z8ZXWltMucCAwEAAaMbMBkwFwYDVR0RBBAwDoIM
         d3d3LnRlc3QuY29tMA0GCSqGSIb3DQEBBQUAA4IBAQB4phluspkjLvLOxGw9Yycw
         V97gvwpqr+JuEIVJL2W3eDsUbLmIpMQ5AhjedJV6z8rjugJJF6/c7slboKj/Awr4
         +l/Gjnkgt7yuOJ4reghiQvveGp9iIKlo2S76juLVxg1pKTLGm7Ult3Z+kz1aQaxS
         o38y3Yqy+b8MO8/mjOOTkm1atvif2XZAn2LiNaApk0kVaJcLov/oxJbzQPwjdxge
         1rN0Mk+qPexa46iP7vJLpVd4BHqf7s0kY5FuiqFmwsGdcHqAmUgmsp3SPHxgCUgC
         Z1pVtB4uciEpLdYesA2cy9kAy1wLJuz9JbdTT1k/ViyreBGdu8mkH7OiqCwJcn+l
         -----END CERTIFICATE-----
        chain: ''
        key: |-
         -----BEGIN RSA PRIVATE KEY-----
         MIIEowIBAAKCAQEAowHbcOUBgjmxfkC6ZhWvWTUYXgBIuYLaRsl8qLpCruks3upm
         LPogD9WFasKvoY4EQ9Ib3cgLFb8PbH/cHgzISYW71xKR6G37lGgmMVfje4QadUxY
         L6iPayvrawFfPrw75dHN5UDFYGcmPiuy2P7VGBm6Vif7/p1PK+R8u5YEzQYmVO3E
         Z/pjT3EZZfDHJOaIchw2yfUGRFENxcyvSZmiAr5RZ2oxdWrp1G5A3fXmvgd0RnzG
         UIx5YL0S58hu2XW2beaNIRDWOFlZ4gAqul0gzK0B22jKYMdSB+RxBajWJO+dhxDg
         5V/TCUKYglQkvD1aM4pKwlbTq6zpnxldaW0y5wIDAQABAoIBAGnTQ9aoJfGYaP3R
         IfIyc9NTYA1u28fsBq9cEZ0sxyvs35+cx1a9z+DXuzUTTZhxrZ0mI8c5HtEwZ+AF
         pi6wF7t7ofY/7Q/bjy/K6bixGVNP8SljtgDCytFGAyFGE8KTy8MpESWbhkhOzwof
         ro2n60opMcrLTJMBJ6wUO1JBU76SDRP2/061SXbdC4MBgO/Ea2J42GjbTtWkTvCp
         sjBKpZbwLJPyIe6eQeqBA9eCgjEFc20owLva6eW/+KSI7sY6t6kAW8EQLAjT3BFa
         1+3AuWTfo2kgXGFO8eYbRE5IYfXAOdI+7laGAGme5Wk1gB4OEgBRmEILDiLesksx
         b9K1l8kCgYEA1CorQ2eAyly6YYAeS/6SWDozugUnTXVMjRCR1uqqfr2Y213HMeUw
         +Q6eIh0xlsEow8HKYHhmZ4uPRStmctm2QpbBCzPl8dpdmcQo5n7ouNELPeSVznmH
         eMnx3b3mtL48PkXziWKm8IoJ/qWFheZjZz5ymhRGzFFiPv4JQVpnl8MCgYEAxK+l
         5eaOhepzEwqDVFPEIy4zmMRfQQHH9qahDHogGQmzdlZ3yrZwOLfJvXskuomVKqhB
         aeDEWd/zLcrQU3QNFTiBZhJgWGutrp/MxwR5ft4Wvm4Xj7EaAdl9Iq1cdLKvyeHw
         8JbYu4KHTTNtNIzIAy0yQdhiKHIq6hucOXfhqg0CgYB1RoH3lkTolu0na+xTUXqP
         bkydbK/W7xnLd/dFdx2bRS4zQ9kRyYCSivP6I2z/yfHAk2RMgwEIB2rAb0cIATPw
         BujaSmu2jl/i2T1Ke6gkUNkH80yjfyXVLLuXOJtIGUevnHcL4A4rNAJmUhRGeZ1E
         uo4agU7JLctCyqVPDKvqhQKBgDnCk2eWc5hkJ3MaDUNAbkMemExursJ6cWy/tl/h
         pXd0390Ku5cuSHp/jqE0fq7BJKsoSj17om36VIHII7G+TPFEbMu67cxJovG7P/na
         GIvnUKqPzh+GlOqiIhuC6bnjl7gjwAwHYJKAXJeRWKqsBTjZlv67OuhBztR9Uz2V
         NRIpAoGBANIn8QeRhIpTx4IOtn+MEI/cHbGHfHjwkidm9KVbyuOgHKSHPZ1jCbTA
         Tr6dWkpbMIkxhkbuTED6UqXmvPxui0ZXgM+MozRgkOEvKaMEjTit7D6xM4ba1wl8
         pbrcUEXSdSRp89NDRUAsyRPCRvMNspGDOqJKXxLus1u3YpiHkD7a
         -----END RSA PRIVATE KEY-----
        passphrase: test

Please note that the "certificate.yaml" file can either be created manually or be generated using the following command:
python cwafctl.py utils generate_yaml_cert_file certificate.pem key.pem certchain.pem test
where certificate.pem is the file containing the public key
where key.pem is the file containing the private key
where certchain.pem is the file containing the certificate chain
where test is the passphrase that was used to encrypt the certificate

**To deploy the certificate:**

    python cwafctl.py create certificate < ./"yaml files"/certificate.yaml

**To deploy the application:**

    python cwafctl.py create application < ./"yaml files"/newapp.yaml












