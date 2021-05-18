import fire
import requests
import json
import urllib
from lxml import html
import http.client
import time
import settings
import yaml
import sys
from OpenSSL.crypto import load_certificate, FILETYPE_PEM


class CloudWAFAPI(object):

  def __init__(self):
    self.tenantID="";
    self.bearerToken="";
    self.oktacookie = None;
    self.username=settings.USER_NAME;
    self.password=settings.PASSWORD;


  def login(self):
    payload = {"username": "","password": "","options": {"multiOptionalFactorEnroll": True,"warnBeforePasswordExpired": True}}
    payload["username"] = self.username;
    payload["password"] = self.password;

    headers = {'Content-Type': 'application/json'}
    data = json.dumps(payload)

    response=requests.request("POST","https://radware-public.okta.com/api/v1/authn",headers=headers, data=data)
    if response.status_code != 200:
      raise Exception("Cannot authenticate to Cloud WAF, invalid credentials")

    responsePayload=response.json()

    ##retrieve tocken and nounce to be used in the authorization request
    sessionToken=responsePayload["sessionToken"]
    nonce=responsePayload["_embedded"]["user"]["id"]

    params = {'client_id': 'M1Bx6MXpRXqsv3M1JKa6','nonce':'','prompt':'none','redirect_uri':'https://portal.radwarecloud.com',
              'response_mode':'form_post','response_type':'token','scope':'api_scope','sessionToken':'','state':'parallel_af0ifjsldkj'}


    params["sessionToken"]=sessionToken
    params["nonce"]=nonce

    ##print("nonce="+nonce)

    ##retrieve the bearerToken to be used for subsequent calls
    response=requests.request("GET","https://radware-public.okta.com/oauth2/aus7ky2d5wXwflK5N1t7/v1/authorize",params=params)
    if response.status_code != 200:
      raise Exception("Not authorized, please make sure you are using a Cloud WAF API account.")

    self.oktacookie=response.cookies

    ###extract bearer token form response
    tree = html.fromstring(response.content)
    self.bearerToken = tree.xpath('//form[@id="appForm"]/input[@name="access_token"]/@value')[0]
    ##print("bearerToken="+self.bearerToken)

    ## Use the bearerToken to retrieve the tenant ID
    headers = {"Authorization": "Bearer %s" % self.bearerToken}

    response=requests.request("GET","https://portal.radwarecloud.com/v1/users/me/summary",headers=headers)
    responsePayload=response.json()

    self.tenantID=responsePayload["tenantEntityId"]

    ##print("tenantID="+self.tenantID)
    ##print("bearerToken="+self.bearerToken)
    ##print("login successful")

  ## Example of a result returned by CWAF
  ##{"numberOfElements":7,"totalElements":7,"page":0,"totalPages":1,"applications":[{"applicationId":"9d8213f6-580f-406c-9bda-618ef9b3896d","applicationName":"Juice Shop","mainDomain":"juice-shop.herokuapp.com","region":"North America (Ashburn)","deploymentStatus":"PROTECTING","creationDate":1617758940383,"frontend":"alcon","customDeployment":false,"accountId":"607b9775-a04a-4efa-ba97-228909abc300","accountName":"US Region PoCs"},{"applicationId":"db3718bc-de94-40c1-9adf-300a41069e44","applicationName":"rs_hackazon","mainDomain":"rsamazon.ddns.net","region":"North America (Ashburn)","deploymentStatus":"PROTECTING","creationDate":1598545097301,"frontend":"alcon","customDeployment":false,"accountId":"607b9775-a04a-4efa-ba97-228909abc300","accountName":"US Region PoCs"},{"applicationId":"fbb1a01a-1693-4f6c-b393-9b2465bf9427","applicationName":"test-radwarelabs.ca","mainDomain":"new-radwarelabs.ca","region":"North America (Ashburn)","deploymentStatus":"PROTECTING","creationDate":1596741939251,"frontend":"alcon","customDeployment":false,"accountId":"607b9775-a04a-4efa-ba97-228909abc300","accountName":"US Region PoCs"},{"applicationId":"b1e6111b-598e-49f8-92dc-59bac3b73d87","applicationName":"Toronto-HacmeBank","mainDomain":"new-hacme.radwarelabs.ca","region":"North America (Toronto)","deploymentStatus":"PROTECTING","creationDate":1583938759419,"frontend":"alcon","customDeployment":false,"accountId":"607b9775-a04a-4efa-ba97-228909abc300","accountName":"US Region PoCs"},{"applicationId":"13e6a064-d9bd-43bb-8ebc-b6dfb6395833","applicationName":"botmgr","mainDomain":"www.botmgr.online","region":"North America (Ashburn)","deploymentStatus":"PROTECTING","creationDate":1557753570459,"frontend":"alcon","customDeployment":false,"accountId":"607b9775-a04a-4efa-ba97-228909abc300","accountName":"US Region PoCs"},{"applicationId":"3ec2e44f-2392-4e2c-8d9c-ef849f782090","applicationName":"radwarelabs.ca","mainDomain":"radwarelabs.ca","region":"North America (Ashburn)","deploymentStatus":"PROTECTING","creationDate":1557165943042,"frontend":"alcon","customDeployment":false,"accountId":"607b9775-a04a-4efa-ba97-228909abc300","accountName":"US Region PoCs"},{"applicationId":"7c1457fc-9324-4d53-bdba-31d8d8a3fa91","applicationName":"HacmeBank","mainDomain":"hacme.radwarelabs.ca","region":"North America (Ashburn)","deploymentStatus":"PROTECTING","creationDate":1521740833216,"frontend":"alteon","customDeployment":false,"accountId":"607b9775-a04a-4efa-ba97-228909abc300","accountName":"US Region PoCs"}]}
  def getApplications(self):

      self.login()
      payload = {"pagination": {"page": 0}, "order": {"field": "creationDate", "order": "DESC"},"statuses": ["PROVISIONING", "PROTECTING", "LEARNING", "DELETING"], "search": ""}

      headers = {
            'Authorization': 'Bearer ' + self.bearerToken,
            'requestEntityids': self.tenantID,
            'Cookie': 'Authorization=' + self.bearerToken,
            'Content-Length': len(json.dumps(payload)),
            'Content-Type': 'application/json;charset=UTF-8'
        }


      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      conn.request("POST", "/v1/gms/applications", json.dumps(payload), headers=headers)
      res = conn.getresponse()
      if res.status != 200:
            raise Exception("Error retrieving application IDs from Cloud WAF")

      appdata = json.loads(res.read().decode())
      self.logout()


      return appdata

  def getApplicationsACLs(self):
      acls={'acls':[]}
      apps=self.getApplications()
      for app in apps['applications']:
        acl=self.getApplicationACL(app['applicationId'])
        acls['acls'].append({'applicationId':app['applicationId'],'applicationName':app['applicationName'],'acl':acl})

      return acls

  def addIPtoAppACLs(self,applicationId,IPaddress):
      ##first retrieve ACL
      acl=self.getApplicationACL(applicationId)
      acl['accessControlListItems'].append({'operation':"BLOCK","ip":IPaddress,"description":"Created from SecureX"})


      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(acl)),
          'Content-Type': 'application/json;charset=UTF-8'
      }
      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      url = "/v1/configuration/applications/" + urllib.parse.quote(applicationId) + "/acl"

      conn.request("PUT", url, json.dumps(acl), headers=headers)
      res = conn.getresponse()
      if res.status != 200:
          raise Exception("Error: Could not add IP to the AccessRules for app: "+applicationId)

  def RemoveIPfromAppACLs(self, applicationId, IPaddress):

      ##first retrieve ACL
      aclarray = self.getApplicationACL(applicationId)
      found = False

      i=0;
      ##remove the IP from the acl returned
      for acl in aclarray['accessControlListItems']:
          if acl['operation']=='BLOCK' and acl['ip']==IPaddress:
              aclarray['accessControlListItems'].pop(i)
              found=True;
              break
          i=i+1
      ##if IP was in ACL, update the app ACL
      if found==True:
        headers = {
            'Authorization': 'Bearer ' + self.bearerToken,
            'requestEntityids': self.tenantID,
            'Cookie': 'Authorization=' + self.bearerToken,
            'Content-Length': len(json.dumps(aclarray)),
            'Content-Type': 'application/json;charset=UTF-8'
        }
        conn = http.client.HTTPSConnection("portal.radwarecloud.com")
        url = "/v1/configuration/applications/" + urllib.parse.quote(applicationId) + "/acl"

        conn.request("PUT", url, json.dumps(aclarray), headers=headers)
        res = conn.getresponse()
        if res.status != 200:
              raise Exception("Error: Could not delete P from the Access Rules for app: " + applicationId)

  def getSecurityPolicies(self):
      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
      }

      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      conn.request("GET", "/v2/gms/policies/", headers=headers)
      res = conn.getresponse()
      if res.status != 200:
          raise Exception("Error retrieving security policies from Cloud WAF")

      appdata = json.loads(res.read().decode())

      return appdata

  def getGeoBlockingPolicies(self):
      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
      }

      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      conn.request("GET", "/v2/gms/policies/geoblocking", headers=headers)
      res = conn.getresponse()
      if res.status != 200:
          raise Exception("Error retrieving geo blocking policies from Cloud WAF")

      appdata = json.loads(res.read().decode())

      return appdata

  def getPolicyDistribution(self):
      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
      }

      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      conn.request("GET", "/v1/configuration/policydistribution", headers=headers)
      res = conn.getresponse()
      if res.status != 200:
          raise Exception("Error retrieving geo blocking policies from Cloud WAF")

      appdata = json.loads(res.read().decode())

      return appdata


  def getUsers(self):
      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
      }

      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      conn.request("GET", "/v1/users?limit=50&after=0", headers=headers)
      res = conn.getresponse()
      if res.status != 200:
          raise Exception("Error retrieving users from Cloud WAF")

      appdata = json.loads(res.read().decode())

      return appdata



  def getCustomerInfo(self):
      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
      }

      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      conn.request("GET", "/v1/gms/customers/"+self.tenantID, headers=headers)
      res = conn.getresponse()
      if res.status != 200:
          raise Exception("Error retrieving geo blocking policies from Cloud WAF")

      appdata = json.loads(res.read().decode())

      return appdata


  def getIPGroups(self):
        headers = {
            'Authorization': 'Bearer ' + self.bearerToken,
            'requestEntityids': self.tenantID,
            'Cookie': 'Authorization=' + self.bearerToken,
        }

        conn = http.client.HTTPSConnection("portal.radwarecloud.com")
        conn.request("GET", "/v2/gms/policies/ipgroup", headers=headers)
        res = conn.getresponse()
        if res.status != 200:
            raise Exception("Error retrieving IP groups from Cloud WAF")

        appdata = json.loads(res.read().decode())

        return appdata

  def UpdateIPGroup(self,ipGroup):


        headers = {
            'Authorization': 'Bearer ' + self.bearerToken,
            'requestEntityids': self.tenantID,
            'Cookie': 'Authorization=' + self.bearerToken,
            'Content-Length': len(json.dumps(ipGroup)),
            'Content-Type': 'application/json;charset=UTF-8'
        }
        conn = http.client.HTTPSConnection("portal.radwarecloud.com")
        url= "/v2/gms/policies/ipgroup/"+ipGroup['templateId']
        conn.request("PUT",url,json.dumps(ipGroup), headers=headers)
        res = conn.getresponse()
        if res.status != 200:
            raise Exception("Error could not upate IP Group in Cloud WAF")

        appdata = json.loads(res.read().decode())

        return;


  def addIPtoIPsGroups(self,groupId,ip):
      ipGroups = self.getIPGroups()
      if ipGroups is None:
          return;
      for ipgroup in ipGroups:
          if ipgroup['templateId']==groupId:
              ipgroup['ipGroupItems'].append({'ip':ip,'description':'Created from Cisco SecureX'})
              self.UpdateIPGroup(ipgroup)

  def removeIPfromIPGroups(self,groupId,ip):
      ipGroups = self.getIPGroups()
      if ipGroups is None:
          return


      for ipgroup in ipGroups:
          if ipgroup['templateId']==groupId:
              i = 0
              for ipaddr in ipgroup['ipGroupItems']:
                  if ipaddr['ip']==ip:
                       ipgroup['ipGroupItems'].pop(i)
                       self.UpdateIPGroup(ipgroup)

                  i = i + 1;

  def getLegitimateBots(self,applicationId):

      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      ## gets the bots for the last month
      payload = {"applications": [{"applicationId": applicationId}], "startTime": "%i"%((int(time.time())-(30*24*60*60))*1000), "endTime": "%i"%((int(time.time()))*1000), "page": 1, "pageSize": 20}


      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(payload)),
          'Content-Type': 'application/json;charset=UTF-8'
      }

      conn.request("POST", "/reporter/reports/antibot/v1/analysis/legitimate-bots", json.dumps(payload), headers=headers)
      res = conn.getresponse()
      if res.status != 200:
          raise Exception("Error retrieving legitimate bots from Cloud WAF")

      events = json.loads(res.read().decode())

      return events

  def getBadBots(self, applicationId):

      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      ## gets the bots for the last month
      payload = {"applications": [{"applicationId": applicationId}],
                 "startTime": "%i" % ((int(time.time()) - (30 * 24 * 60 * 60)) * 1000),
                 "endTime": "%i" % ((int(time.time())) * 1000), "page": 1, "pageSize": 20}

      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(payload)),
          'Content-Type': 'application/json;charset=UTF-8'
      }

      conn.request("POST", "/reporter/reports/antibot/v1/analysis/bad-bots", json.dumps(payload),
                   headers=headers)
      res = conn.getresponse()
      if res.status != 200:
          raise Exception("Error retrieving legitimate bots from Cloud WAF")

      events = json.loads(res.read().decode())

      return events

  def getSearchEngineBots(self,applicationId):
      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      ## gets the bots for the last month
      payload = {"applications": [{"applicationId": applicationId}],
                 "startTime": "%i" % ((int(time.time()) - (30 * 24 * 60 * 60)) * 1000),
                 "endTime": "%i" % ((int(time.time())) * 1000), "page": 1, "pageSize": 20}

      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(payload)),
          'Content-Type': 'application/json;charset=UTF-8'
      }

      conn.request("POST", "/reporter/reports/antibot/v1/analysis/search-engine-bots", json.dumps(payload),headers=headers)
      res = conn.getresponse()
      if res.status != 200:
          raise Exception("Error retrieving legitimate bots from Cloud WAF")

      events = json.loads(res.read().decode())

      return events

  ##not working: TODO: open a support ticket with Radware
  def getActivityLogs(self):

      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      ## gets the logs for the last 90 days
      payload= {"order": [{"type": "Order", "order": "DESC", "field": "startDate"}],
                 "pagination": {"size": 100, "page": 0},"criteria": [{"type": "timeFilter",
                 "field": "startDate", "includeLower": True, "includeUpper": True,
                 "upper":  "%i" % ((int(time.time())) * 1000), "lower": "%i" % ((int(time.time()) - (90 * 24 * 60 * 60)) * 1000)}]}



      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestentityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(payload)),
          'Content-Type': 'application/json;charset=UTF-8'
      }

      conn.request("POST", "/v1/userActivityLogs/reports/", json.dumps(payload),headers=headers)
      res = conn.getresponse()
      if res.status != 200:
          print("Error retrieving activity logs from Cloud WAF")
          print(res.read().decode())
          return

      events = json.loads(res.read().decode())

      return events


  def getEventsWAF(self,sourceIP="",applicationId=""):

      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      pageNumber = 0

      payload = {"criteria":[],"pagination":{"page":0,"size":0},"order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}

      ##build the search criterias
      if applicationId!="":
          payload['criteria'].append({"type":"orFilter","filters":[{"type":"termFilter","inverseFilter":False,"field":"enrichmentContainer.applicationId","value":applicationId}]})

      if sourceIP!="":
          payload['criteria'].append({'type': "likeFilter", 'inverseFilter': False, 'field': "externalIp", 'value': sourceIP})

      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(payload)),
          'Content-Type': 'application/json;charset=UTF-8'
      }

      conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", json.dumps(payload), headers=headers)
      res = conn.getresponse()
      if res.status != 200:
          raise Exception("Error retrieving events from Cloud WAF")

      events = json.loads(res.read().decode())

      return events

  def getEventsDDoS(self,sourceIP="",destinationIP="",applicationId=""):
      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      pageNumber = 0

      payload = {"criteria":[],"pagination":{"page":0,"size":0},"order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}

      ##build the search criterias
      if applicationId!="":
          payload['criteria'].append({"type": "termFilter","inverseFilter": False,"field": "enrichmentContainer.applicationId","value": applicationId})

      if sourceIP!="":
          payload['criteria'].append({"type": "likeFilter", "inverseFilter": False, "field": "source_address", "value": sourceIP})

      if destinationIP!="":
          payload['criteria'].append({"type": "likeFilter", "inverseFilter": False, "field": "destination_address", "value": destinationIP})



      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(payload)),
          'Content-Type': 'application/json;charset=UTF-8'
      }

      conn.request("POST", "/mgmt/monitor/reporter/reports-ext/SYSTEM_ATTACK", json.dumps(payload), headers=headers)
      res = conn.getresponse()
      if res.status != 200:
          raise Exception("Error retrieving events from Cloud WAF")

      events = json.loads(res.read().decode())

      return events



  ##timelower and time upper are UTC timestamps in millisecs
  def getEventsBySourceIP(self,timelower,timeupper,sourceIP):

    events={"data":[]}
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    pageNumber=0

    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":'''+timeupper+''',"lower":'''+timelower+'''},{"type":"likeFilter","inverseFilter":false,"field":"externalIp","value":'''+"\""+sourceIP+"\""+'''}],"pagination":{"page":'''+"%s"%pageNumber+''',"size":100},"order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''

    headers = {
        'Authorization': 'Bearer ' + self.bearerToken,
        'requestEntityids': self.tenantID,
        'Cookie': 'Authorization=' + self.bearerToken,
        'Content-Length': len(payload),
        'Content-Type': 'application/json;charset=UTF-8'
    }


    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
       raise Exception("Error retrieving events from Cloud WAF")


    appdata = json.loads(res.read().decode())
    i=0
    for row in appdata["data"]:
       events["data"].append(appdata["data"][i])
       i=i+1

    if len(appdata["data"]) == 0:
       return events;

    pageNumber=pageNumber+1


    return events


  def logout(self):
    if self.oktacookie is not None:
      headers = {'Content-Type': 'application/json,text/plain,*/*'}
      response = requests.request("DELETE", "https://radware-public.okta.com/api/v1/sessions/me", headers=headers,cookies=self.oktacookie)

    return

  def deleteApplication(self,AppID):
      self.login()

      conn = http.client.HTTPSConnection("portal.radwarecloud.com")

      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
      }
      conn.request("DELETE", "/v1/gms/applications/" + AppID, headers=headers)
      res = conn.getresponse()
      if res.code != 200:
          raise Exception("Error: Cannot delete application from Cloud WAF")

      appdata = res.read()
      self.logout()

      return


  def getApplication(self,AppID):

    self.login()
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")

    headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
        'requestEntityids': self.tenantID,
        'Cookie': 'Authorization=' + self.bearerToken,
    }
    conn.request("GET", "/v1/gms/applications/" + AppID, headers=headers)
    res = conn.getresponse()
    if res.code != 200:
          raise Exception("Error: Cannot retrieve application objects from Cloud WAF")

    appdata = res.read()
    self.logout()

    return json.loads(appdata)

  def getApplication_v2(self,AppID):
      self.login()
      conn = http.client.HTTPSConnection("portal.radwarecloud.com")

      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
      }
      conn.request("GET", "/v2/configuration/applications/" + AppID, headers=headers)
      res = conn.getresponse()
      if res.code != 200:
          raise Exception("Error: Cannot retrieve application v2 objects from Cloud WAF")

      appdata = res.read()
      self.logout()

      return json.loads(appdata)



  def createApplication(self,app):

      ##payload={"applicationName":"","mainDomain":"","protocol":"","region":"","originServers":[],"addressType":"","generalInfo":{"ownerName":"","ownerEmail":"","externalID":"","description":"","fingerprint":""}}

      payload=app;

      self.login()

      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(payload)),
          'Content-Type': 'application/json;charset=UTF-8'
      }

      ##print(json.dumps(payload))

      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      conn.request("POST", "/v1/configuration/applications/", json.dumps(payload), headers=headers)
      res = conn.getresponse()
      if res.code != 200:
          print(res.read())
          raise Exception("Error: Could not create application Cloud WAF")

      self.logout()

      appdata = res.read()
      return json.loads(appdata)



  def uploadCertificate(self,certificate):

      payload=certificate

      self.login()
      conn = http.client.HTTPSConnection("portal.radwarecloud.com")


      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(payload)),
          'Content-Type': 'application/json;charset=UTF-8',
          'selfsigned':'true'
      }

      conn.request("POST", "/v1/configuration/sslcertificates/secret", json.dumps(payload), headers=headers)
      res = conn.getresponse()
      if res.code != 200:
          ##print(payload)
          ##print(res.read())
          raise Exception("Error: Could not upload cerficate to Cloud WAF")

      appdata = res.read()
      ##print("Certificate was successfully uploaded to CloudWAF\n")
      self.logout()
      return json.loads(appdata)

  def deleteCertificate(self,fingerprint):
      self.login()

      conn = http.client.HTTPSConnection("portal.radwarecloud.com")

      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
      }
      conn.request("DELETE", "/v1/configuration/sslcertificates/" + fingerprint, headers=headers)
      res = conn.getresponse()
      if res.code != 200:
          raise Exception("Error: Cannot delete application from Cloud WAF")

      appdata = res.read()
      self.logout()
      print("Certificate was successfully deleted from CloudWAF\n")
      return


  def getCertificates(self):

      self.login()
      conn = http.client.HTTPSConnection("portal.radwarecloud.com")

      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
      }
      conn.request("GET", "/v1/configuration/sslcertificates/", headers=headers)
      res = conn.getresponse()
      if res.code != 200:
          raise Exception("Error: Cannot retrieve certificates objects from Cloud WAF")

      appdata = res.read()
      self.logout()
      return json.loads(appdata)

  def updateApplication(self,application):
      conn = http.client.HTTPSConnection("portal.radwarecloud.com")

      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(application)),
          'Content-Type': 'application/json;charset=UTF-8'
      }
      conn.request("PUT", "/v1/gms/applications/" + AppID,json.dumps(application),headers=headers)
      res = conn.getresponse()
      if res.code != 200:
          raise Exception("Error: Cannot update application object from Cloud WAF")

      appdata = res.read()

  def updateProtocolsSecurity(self,AppID,protocolSecurity):
      conn = http.client.HTTPSConnection("portal.radwarecloud.com")

      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(protocolSecurity)),
          'Content-Type': 'application/json;charset=UTF-8'
      }
      conn.request("PUT", "/v1/configuration/applications/" + AppID+"/securityManagement/bind",json.dumps(protocolSecurity) ,headers=headers)
      res = conn.getresponse()
      if res.code != 200:
          raise Exception("Error: Cannot update Protocol Security settings from the application object from Cloud WAF")

      appdata = res.read()


  def updateApplicationOriginServers(self,AppID,originServers):
      conn = http.client.HTTPSConnection("portal.radwarecloud.com")

      if originServers['mode']=='LOAD_BALANCE':
        url="/operationmode/loadbalance"
        payload={'serverAddresses':originServers['loadBalanceMode']['serverAddresses']}
      elif originServers['mode']=='FAILOVER':
          url="/operationmode/failover"
          payload={'primaryAddress':originServers['failoverMode']['primaryAddress'],'secondaryAddress':originServers['failoverMode']['secondaryAddress']}
      else:
         raise Exception("Error: Cloud WAF returned an unsupported method of load balancing traffic to Origin Servers")

      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(payload)),
          'Content-Type': 'application/json;charset=UTF-8'
      }
      conn.request("PUT", "/v1/configuration/applications/" + AppID+url,json.dumps(payload) ,headers=headers)
      res = conn.getresponse()
      if res.code != 200:
          raise Exception("Error: Cannot update origin servers from the application object from Cloud WAF")

      appdata = res.read()

  def IsIPaddressInApplicationACL(self,ipaddress):
      app=self.getApplicationACL()
      for operation in app['accessControlListItems']:
          if operation['operation']=='BLOCK' and operation['ip']==ipaddress:
              return True;

      return False;


  def getApplicationACL(self,AppId):
    app=self.getApplication(AppId)
    ##"accessRules":{"accessRules":[]},"accessControlList":{"accessControlListItems":[{"operation":"BLOCK","ip":"1.1.1.1","description":"Tentative SQLMap attack. "},{"operation":"BLOCK","ip":"2.2.2.2","description":"Malicious IP,"},{"operation":"BLOCK","ip":"3.3.3.3","description":"test"}]
    operations=app['featuresData']['wafFeatureData']['accessControlList']

    return operations;




  def getApplicationHost(self, AppID):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
    }
    conn.request("GET", "/v1/gms/applications/" + AppID, headers=headers)
    res = conn.getresponse()
    if res.code != 200:
      raise Exception("Error: Cannot retrieve application objects from Cloud WAF")

    appdata = res.read()

    try:
      domainName=json.loads(appdata)['featuresData']['wafFeatureData']['mainDomain']['mainDomain']
    except Exception as e:
        domainName=""

    return domainName;

  def updateGeneralInfo(self,AppId,GeneralInfo):
      conn = http.client.HTTPSConnection("portal.radwarecloud.com")

      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(GeneralInfo)),
          'Content-Type': 'application/json;charset=UTF-8'
      }
      conn.request("PUT", "/v1/gms/applications/" + AppId +"/generalInfo", json.dumps(GeneralInfo), headers=headers)
      res = conn.getresponse()
      if res.code != 200:
          raise Exception("Error: Cannot update generalInfo object from Cloud WAF")

      appdata = res.read()
      return appdata

  def updateMainDomain(self,AppId,MainDomain):
      conn = http.client.HTTPSConnection("portal.radwarecloud.com")

      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(MainDomain)),
          'Content-Type': 'application/json;charset=UTF-8'
      }
      conn.request("PUT", "/v1/configuration/applications/regularDeployment/" + AppId +"/mainDomain", json.dumps(MainDomain), headers=headers)
      res = conn.getresponse()
      if res.code != 200:
          raise Exception("Error: Cannot update mainDomain object from Cloud WAF")

      appdata = res.read()
      return appdata

  def updateProtocolsAndHealthChecks(self,AppId,ProtocolsAndHealthChecks):
      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(ProtocolsAndHealthChecks)),
          'Content-Type': 'application/json;charset=UTF-8'
      }
      conn.request("PUT", "/v1/configuration/applications/" + AppId +"/protocol", json.dumps(ProtocolsAndHealthChecks), headers=headers)
      res = conn.getresponse()
      if res.code != 200:
          raise Exception("Error: Cannot update protocols and health checks object from Cloud WAF")

      appdata = res.read()
      return appdata

  def updateTrueClientIP(self,AppId,TrueClientIP):
      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(TrueClientIP)),
          'Content-Type': 'application/json;charset=UTF-8'
      }
      conn.request("PUT", "/v1/configuration/applications/" + AppId +"/sourceIpHeader", json.dumps(TrueClientIP), headers=headers)
      res = conn.getresponse()
      if res.code != 200:
          raise Exception("Error: Cannot update protocols and health checks object from Cloud WAF")

      appdata = res.read()
      return appdata

  def updateIPPeristency(self,AppId,IPPersistency):
      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(IPPersistency)),
          'Content-Type': 'application/json;charset=UTF-8'
      }
      conn.request("PUT", "/v1/configuration/applications/" + AppId +"/ipPersistency", json.dumps(IPPersistency), headers=headers)
      res = conn.getresponse()
      if res.code != 200:
          raise Exception("Error: Cannot update ip persistency settings from Cloud WAF")

      appdata = res.read()
      return appdata

  def updateSecurityBypass(self,AppId,securityBypass):
      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(securityBypass)),
          'Content-Type': 'application/json;charset=UTF-8'
      }
      conn.request("PUT", "/v1/configuration/applications/" + AppId +"/accessRules", json.dumps(securityBypass), headers=headers)
      res = conn.getresponse()
      if res.code != 200:
          raise Exception("Error: Cannot update security bypass settings from Cloud WAF")

      appdata = res.read()
      return appdata

  def updateAccessRules(self,AppId,accessRules):
      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(accessRules)),
          'Content-Type': 'application/json;charset=UTF-8'
      }
      conn.request("PUT", "/v1/configuration/applications/" + AppId +"/acl", json.dumps(accessRules), headers=headers)
      res = conn.getresponse()
      if res.code != 200:
          raise Exception("Error: Cannot update access rules settings from Cloud WAF")

      appdata = res.read()
      return appdata

  def updateDatabaseProtectionStatus(self,AppId,status):
      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      payload={'protectionStatus':status}

      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(payload)),
          'Content-Type': 'application/json;charset=UTF-8'
      }
      conn.request("PUT", "/v1/configuration/applications/" + AppId +"/protections/databaseProtection/status", json.dumps(payload), headers=headers)
      res = conn.getresponse()
      if res.code != 200:
          raise Exception("Error: Cannot update database protection from Cloud WAF")

      appdata = res.read()
      return appdata


  def updateDatabaseProtectionList(self,AppId,dbProtection):
      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(dbProtection)),
          'Content-Type': 'application/json;charset=UTF-8'
      }
      conn.request("PUT", "/v1/configuration/applications/" + AppId +"/protections/databaseProtection/databaseList", json.dumps(dbProtection), headers=headers)
      res = conn.getresponse()
      if res.code != 200:
          raise Exception("Error: Cannot update database protection from Cloud WAF")

      appdata = res.read()
      return appdata

  def updateVulnerabilityProtectionStatus(self,AppId,status):
      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      payload={'protectionStatus':status}

      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(payload)),
          'Content-Type': 'application/json;charset=UTF-8'
      }
      conn.request("PUT", "/v1/configuration/applications/" + AppId +"/protections/vulnerabilityProtection/status", json.dumps(payload), headers=headers)
      res = conn.getresponse()
      if res.code != 200:
          raise Exception("Error: Cannot update vulnerability protection status from Cloud WAF")

      appdata = res.read()
      return appdata

  def updateVulnerabilityProtectionList(self,AppId,vulProtection):
      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(vulProtection)),
          'Content-Type': 'application/json;charset=UTF-8'
      }
      conn.request("PUT", "/v1/configuration/applications/" + AppId +"/protections/vulnerabilityProtection/vulnerabilityList", json.dumps(vulProtection), headers=headers)
      res = conn.getresponse()
      if res.code != 200:
          raise Exception("Error: Cannot update vulnerability protection list from Cloud WAF")

      appdata = res.read()
      return appdata

  def updateAllowedUrlsProtectionStatus(self,AppId,status):
      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      payload = {'protectionStatus': status}

      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(payload)),
          'Content-Type': 'application/json;charset=UTF-8'
      }
      conn.request("PUT", "/v1/configuration/applications/" + AppId + "/protections/allowedFileExtensionProtection/status",
                   json.dumps(payload), headers=headers)
      res = conn.getresponse()
      if res.code != 200:
          raise Exception("Error: Cannot update allowed urls protection status from Cloud WAF")

      appdata = res.read()
      return appdata

  def updateAllowedUrlsProtectionList(self,AppId,allowUrlProt):
      conn = http.client.HTTPSConnection("portal.radwarecloud.com")
      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(allowUrlProt)),
          'Content-Type': 'application/json;charset=UTF-8'
      }
      conn.request("PUT",
                   "/v1/configuration/applications/" + AppId + "/protections/allowedFileExtensionProtection/allowlist/",
                   json.dumps(allowUrlProt), headers=headers)
      res = conn.getresponse()
      if res.code != 200:
          raise Exception("Error: Cannot update allowed urls protection list from Cloud WAF")

      appdata = res.read()
      return appdata


  def updateAnonymousProxyProtectionStatus(self,AppId,anonProxyProt):
      conn = http.client.HTTPSConnection("portal.radwarecloud.com")

      payload={'protectionStatus':anonProxyProt}

      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(payload)),
          'Content-Type': 'application/json;charset=UTF-8'
      }
      conn.request("PUT",
                   "/v1/configuration/applications/" + AppId + "/protections/ipReputationProtection/status/",
                   json.dumps(payload), headers=headers)
      res = conn.getresponse()
      if res.code != 200:
          raise Exception("Error: Cannot update the anonymous protection status from Cloud WAF")

      appdata = res.read()
      return appdata

  def updateSecurityPageUrl(self,AppId,blockURL):
      conn = http.client.HTTPSConnection("portal.radwarecloud.com")

      payload={'url':blockURL}

      headers = {
          'Authorization': 'Bearer ' + self.bearerToken,
          'requestEntityids': self.tenantID,
          'Cookie': 'Authorization=' + self.bearerToken,
          'Content-Length': len(json.dumps(payload)),
          'Content-Type': 'application/json;charset=UTF-8'
      }

      if blockURL!="":
            conn.request("PUT","/v1/configuration/applications/" + AppId + "/securityPage",json.dumps(payload), headers=headers)

      else:
           del headers['Content-Length']
           del headers['Content-Type']
           conn.request("DELETE","/v1/configuration/applications/" + AppId + "/securityPage", headers=headers)


      res = conn.getresponse()
      if res.code != 200:
          raise Exception("Error: Cannot update the securityPage URL from Cloud WAF")

      appdata = res.read()
      return appdata


class create(object):

    def __init__(self):
        self.cwaf = CloudWAFAPI()
        self.certId=0;
        return

    def certificate(self):
        """deploy an certificate using a configuration stored in a yaml file. ex.: python cwafctl.py create certificate < file.yaml"""
        self.cwaf.login()
        certificate = yaml.load(sys.stdin, Loader=yaml.FullLoader)
        cert=self.cwaf.uploadCertificate(certificate)
        self.cwaf.logout()
        ##return yaml.dump(cert)
        return cert['fingerprint']

    def application(self,certFingerprint=""):
        """deploy an application using a configuration stored in a yaml file ex.: python cwafctl.py create application < file.yaml. The certFingerprint parameter allows to override the fingerprint included in the yaml file"""

        self.cwaf.login()

        app = yaml.load(sys.stdin,Loader=yaml.FullLoader)
        if certFingerPrint!="":
            app['fingerprint']=certFingerprint

        app=self.cwaf.createApplication(app)
        self.cwaf.logout()
        return yaml.dump(app)





class delete(object):

    cwaf = CloudWAFAPI()

    def __init__(self):
        return

    def application(self,id):
        """Deletes an certificate by id"""
        self.cwaf.login()
        self.cwaf.deleteApplication(id)
        self.cwaf.logout()

    def certificate(self,fingerprint):
        """Deletes a certificate by fingerprint"""
        self.cwaf.login()
        self.cwaf.deleteCertificate(fingerprint)
        self.cwaf.logout()




class set(object):

    cwaf = CloudWAFAPI()

    def __init__(self):
        return

    def application_generalinfo(self,name):
        """Updates an application general information section via YAML"""
        self.cwaf.login()
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        generalInfo = yaml.load(sys.stdin, Loader=yaml.FullLoader)
        self.cwaf.updateGeneralInfo(id,generalInfo)
        self.cwaf.logout()


    def application_domain(self,name):
        """Updates an application domain name section via YAML"""
        self.cwaf.login()
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        mainDomain = yaml.load(sys.stdin, Loader=yaml.FullLoader)
        self.cwaf.updateMainDomain(id,mainDomain)
        self.cwaf.logout()

    def application_protocols_and_health_checks(self,name):
        """Updates an application protocol and health checks in YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        mainDomain = yaml.load(sys.stdin, Loader=yaml.FullLoader)
        self.cwaf.updateProtocolsAndHealthChecks(id,mainDomain)
        app = self.cwaf.getApplication(id)
        self.cwaf.logout()

    def application_protocol_security(self,name):
        """Updates an application' protocols security configuration  section via YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        protocolSecurity = yaml.load(sys.stdin, Loader=yaml.FullLoader)
        self.cwaf.updateProtocolsSecurity(id,protocolSecurity)
        app = self.cwaf.getApplication(id)
        self.cwaf.logout()
        return

    def application_true_client_ip(self,name):
        """Updates an application' True Client IP settings section via YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        trueClientIP = yaml.load(sys.stdin, Loader=yaml.FullLoader)
        self.cwaf.updateTrueClientIP(id,trueClientIP)
        self.cwaf.logout()
        return

    def application_origin_servers(self,name):
        """Updates an application's origin server settings section via YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        originServers = yaml.load(sys.stdin, Loader=yaml.FullLoader)
        self.cwaf.updateApplicationOriginServers(id,originServers)
        self.cwaf.logout()
        return

    def application_ip_persistency(self,name):
        """Updates an application's ip persistency settings section via YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        ipPersistency = yaml.load(sys.stdin, Loader=yaml.FullLoader)
        self.cwaf.updateIPPeristency(id,ipPersistency)
        self.cwaf.logout()
        return

    def application_security_bypass(self,name):
        """Updates an application's security bypass settings section via YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        securityBypass = yaml.load(sys.stdin, Loader=yaml.FullLoader)
        self.cwaf.updateSecurityBypass(id,securityBypass)
        self.cwaf.logout()
        return

    def application_access_rules(self,name):
        """Updates an application's access rules settings section via YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        accessRules = yaml.load(sys.stdin, Loader=yaml.FullLoader)
        self.cwaf.updateAccessRules(id,accessRules)
        self.cwaf.logout()
        return

    def application_protection_database(self,name):
        """Updates an application's database protection section via YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        dbProtection = yaml.load(sys.stdin, Loader=yaml.FullLoader)
        self.cwaf.updateDatabaseProtectionStatus(id,dbProtection['protectionStatus'])
        self.cwaf.updateDatabaseProtectionList(id,dbProtection['databaseProtectionList'])
        self.cwaf.logout()
        return


    def application_protection_vulnerabilities(self,name):
        """Updates an application's vulnerabilities protection section via YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        vulProtection = yaml.load(sys.stdin, Loader=yaml.FullLoader)
        self.cwaf.updateVulnerabilityProtectionStatus(id,vulProtection['protectionStatus'])
        self.cwaf.updateVulnerabilityProtectionList(id,vulProtection['vulnerabilityList'])
        self.cwaf.logout()
        return

    def application_protection_allowed_urls(self,name):
        """Updates an application's allowed urls protection section via YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        allowedUrlsProtection = yaml.load(sys.stdin, Loader=yaml.FullLoader)
        self.cwaf.updateAllowedUrlsProtectionStatus(id,allowedUrlsProtection['protectionStatus'])
        self.cwaf.updateAllowedUrlsProtectionList(id,allowedUrlsProtection['allowList'])
        self.cwaf.logout()
        return

    def application_protection_anonymous_proxy(self,name):
        """Updates an application's anonymous proxy protection section via YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        anonProxyProtection = yaml.load(sys.stdin, Loader=yaml.FullLoader)
        self.cwaf.updateAnonymousProxyProtectionStatus(id,anonProxyProtection['protectionStatus'])
        self.cwaf.logout()
        return

    def application_security_page(self,name):
        """Updates an application's security page via YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        securityPage = yaml.load(sys.stdin, Loader=yaml.FullLoader)
        self.cwaf.updateSecurityPageUrl(id, securityPage['url'])
        self.cwaf.logout()
        return



class get(object):

    cwaf = CloudWAFAPI()

    def __init__(self):
        return

    def events_waf(self,sourceIP="",applicationName=""):
        """Retrieves WAF events from Cloud WAF"""
        self.cwaf.login()
        applicationId=""
        if applicationName!="":
            apps = self.cwaf.getApplications();
            for app in apps['applications']:
                if app['applicationName'] == applicationName:
                    applicationId = app['applicationId']
                    break
            if id == '':
                print("Error: application: " + name + " could not be found")
                return

        events = self.cwaf.getEventsWAF(sourceIP,applicationId)
        self.cwaf.logout()
        return yaml.dump(events)

    def events_ddos(self,sourceIP="",destinationIP="",applicationName=""):
        "Retrieves DDoS events from Cloud WAF"
        self.cwaf.login()
        applicationId = ""
        if applicationName != "":
            apps = self.cwaf.getApplications();
            for app in apps['applications']:
                if app['applicationName'] == applicationName:
                    applicationId = app['applicationId']
                    break
            if id == '':
                print("Error: application: " + name + " could not be found")
                return
        events = self.cwaf.getEventsDDoS(sourceIP,destinationIP,applicationId)
        self.cwaf.logout()
        return yaml.dump(events)



    def certificates(self):
        """Gets the list of certificates deployed in CWAF in YAML format"""
        self.cwaf.login()
        certificates = self.cwaf.getCertificates()
        self.cwaf.logout()
        return yaml.dump(certificates)

    def applications(self):
        """Gets the current list of applications in YAML format"""
        self.cwaf.login()
        apps = self.cwaf.getApplications()
        self.cwaf.logout()
        return yaml.dump(apps)

    def application_by_id(self,id):
        """Gets an application configuration by ID in YAML"""
        self.cwaf.login();
        app=self.cwaf.getApplication(id)
        self.cwaf.logout()
        return yaml.dump(app)


    def application_by_id_v2(self,id):
        """Gets an application configuration by ID in YAML"""
        self.cwaf.login();
        app=self.cwaf.getApplication_v2(id)
        self.cwaf.logout()
        return yaml.dump(app)

    def application(self,name):
        """Gets an application configuration by name in YAML"""
        self.cwaf.login()
        apps=self.cwaf.getApplications();
        id=''
        for app in apps['applications']:
             if app['applicationName'] == name:
                id=app['applicationId']
                break
        if id=='':
            print("Error: application: "+name+" could not be found")
            return
        self.cwaf.logout()

        return self.application_by_id(id)

    def application_v2(self,name):
        """Gets an application v2 configuration by name in YAML"""
        self.cwaf.login()
        apps=self.cwaf.getApplications();
        id=''
        for app in apps['applications']:
             if app['applicationName'] == name:
                id=app['applicationId']
                break
        if id=='':
            print("Error: application: "+name+" could not be found")
            return
        self.cwaf.logout()

        return self.application_by_id_v2(id)

    def application_acl(self,name):
        """Gets an application ACL by name in YAML"""
        self.cwaf.login();
        apps=self.cwaf.getApplications();
        id=''
        for app in apps['applications']:
             if app['applicationName'] == name:
                id=app['applicationId']
                break
        if id=='':
            print("Error: application: "+name+" could not be found")
            return

        appACL=self.cwaf.getApplicationACL(id)
        self.cwaf.logout()
        return yaml.dump(appACL)

    def application_generalinfo(self,name):
        """Gets an application general info by name in YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id=''
        for app in apps['applications']:
             if app['applicationName'] == name:
                id=app['applicationId']
                break
        if id=='':
            print("Error: application: "+name+" could not be found")
            return

        app=self.cwaf.getApplication(id)
        self.cwaf.logout()
        return yaml.dump(app['generalInfo'])

    def application_domain(self,name):
        """Gets an application main domain in YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        app = self.cwaf.getApplication(id)
        self.cwaf.logout()
        return yaml.dump(app['featuresData']['wafFeatureData']['mainDomain'])

    def application_protocols_and_health_checks(self,name):
        """Gets an application protocol and health checks in YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        app = self.cwaf.getApplication(id)
        self.cwaf.logout()
        return yaml.dump(app['featuresData']['wafFeatureData']['protocol'])

    def application_protocol_security(self,name):
        """Gets an application protocol security info (ex.:TLS settings) in YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        app = self.cwaf.getApplication(id)
        self.cwaf.logout()
        del app['applicationSecuritySettings']['securityProtocolSet']['defaultSet']
        return yaml.dump({'cipherSuiteName':app['applicationSecuritySettings']['cipherSuite']['name'],'securityProtocolSet':app['applicationSecuritySettings']['securityProtocolSet'],'useDefaultCipherSuite':app['applicationSecuritySettings']['useDefaultCipherSuite'],'useDefaultProtocolSet':app['applicationSecuritySettings']['useDefaultProtocolSet']})


    def application_true_client_ip(self,name):
        """Gets the application's true client ip settings in YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        app = self.cwaf.getApplication(id)
        self.cwaf.logout()
        return yaml.dump(app['featuresData']['wafFeatureData']['sourceIpHeader'])

    def application_origin_servers(self,name):
        """Gets the application's origin servers settings in YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        app = self.cwaf.getApplication(id)
        self.cwaf.logout()
        return yaml.dump(app['featuresData']['wafFeatureData']['operationMode'])

    def application_ip_persistency(self,name):
        """Gets the application's persistency settings in YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        app = self.cwaf.getApplication(id)
        self.cwaf.logout()
        return yaml.dump(app['ipPersistencySettings'])

    def application_security_bypass(self,name):
        """Gets the application's security bypass settings in YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        app = self.cwaf.getApplication(id)
        self.cwaf.logout()
        return yaml.dump(app['featuresData']['wafFeatureData']['accessRules'])

    def application_access_rules(self,name):
        """Gets the application's access rules settings in YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        app = self.cwaf.getApplication(id)
        self.cwaf.logout()
        return yaml.dump(app['featuresData']['wafFeatureData']['accessControlList'])

    def application_protection_database(self,name):
        """Gets the application's database protection settings in YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        app = self.cwaf.getApplication_v2(id)
        self.cwaf.logout()
        return yaml.dump(app['featuresData']['wafFeatureData']['protectionConfiguration']['databaseProtection'])

    def application_protection_vulnerabilities(self,name):
        """Gets the application's vulnerability protection settings in YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        app = self.cwaf.getApplication_v2(id)
        self.cwaf.logout()
        return yaml.dump(app['featuresData']['wafFeatureData']['protectionConfiguration']['vulnerabilityProtection'])

    def application_protection_allowed_urls(self,name):
        """Gets the application's allowed URLs protection settings in YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        app = self.cwaf.getApplication_v2(id)
        self.cwaf.logout()
        return yaml.dump(app['featuresData']['wafFeatureData']['protectionConfiguration']['allowedFileExtensionProtection'])

    def application_protection_ddos(self,name):
        """Gets the application's ddos protection settings in YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        app = self.cwaf.getApplication_v2(id)
        self.cwaf.logout()
        return yaml.dump(app['featuresData']['wafFeatureData']['protectionConfiguration']['ddosProtection'])

    def application_protection_http_compliance(self,name):
        """Gets the application's HTTP compliance protection settings in YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        app = self.cwaf.getApplication_v2(id)
        self.cwaf.logout()
        return yaml.dump(app['featuresData']['wafFeatureData']['protectionConfiguration']['httpProtocolComplianceProtection'])

    def application_protection_anonymous_proxy(self,name):
        """Gets the application's Anonymous proxy blocking protection settings in YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        app = self.cwaf.getApplication_v2(id)
        self.cwaf.logout()
        return yaml.dump(app['featuresData']['wafFeatureData']['protectionConfiguration']['ipReputationProtection'])

    def application_protection_anti_bot(self,name):
        """Gets the application's anti-bot protection settings in YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        app = self.cwaf.getApplication_v2(id)
        self.cwaf.logout()
        return yaml.dump(app['featuresData']['wafFeatureData']['protectionConfiguration']['antibotProtection'])



    def application_protection_ert_attackers_feed(self,name):
        """Gets the application's ert attackers feed settings in YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be ound")
            return

        app = self.cwaf.getApplication_v2(id)
        self.cwaf.logout()
        return yaml.dump(app['attackersFeed'])

    def application_protection_api(self,name):
        """Gets the application's API protection settings in YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        app = self.cwaf.getApplication_v2(id)
        self.cwaf.logout()
        return yaml.dump(app['apiProtection'])

    def application_security_page(self,name):
        """Gets the application's blocking page settings in YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        app = self.cwaf.getApplication_v2(id)
        self.cwaf.logout()
        return yaml.dump(app['featuresData']['wafFeatureData']['blockPage'])

    def application_dns_records(self,name):
        """Gets the application's dns diversion records in YAML"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == name:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + name + " could not be found")
            return

        app = self.cwaf.getApplication_v2(id)
        self.cwaf.logout()
        return yaml.dump(app['featuresData']['wafFeatureData']['dns'])

    def templates_ip_groups(self):
        """Get IP group templates in YAML"""
        self.cwaf.login();
        ipgroups = self.cwaf.getIPGroups()
        self.cwaf.logout()
        return yaml.dump(ipgroups)

    def templates_security_policies(self):
        """Get security policies templates in YAML"""
        self.cwaf.login();
        ipgroups = self.cwaf.getSecurityPolicies()
        self.cwaf.logout()
        return yaml.dump(ipgroups)

    def templates_geo_blocking(self):
        """Get geoblocking policies templates in YAML"""
        self.cwaf.login();
        ipgroups = self.cwaf.getGeoBlockingPolicies()
        self.cwaf.logout()
        return yaml.dump(ipgroups)

    def policy_distribution(self):
        """Get policy distribution settings in YAML"""
        self.cwaf.login();
        ipgroups = self.cwaf.getPolicyDistribution()
        self.cwaf.logout()
        return yaml.dump(ipgroups)

    def available_regions(self):
        """Get a list of the available regions for this customer account. Useful to get the right region codes before deploying an app."""
        self.cwaf.login();
        customerInfo=self.cwaf.getCustomerInfo();
        self.cwaf.logout()
        return yaml.dump(customerInfo['availableRegions'])

    def customer_info(self):
        """Gets the customer information for the current account."""
        self.cwaf.login();
        customerInfo = self.cwaf.getCustomerInfo();
        self.cwaf.logout()
        return yaml.dump(customerInfo)

    def legitimate_bots(self,appName,timeLower="",timeUpper=""):
        """Gets the list of observed legitimate bots for the application name provided"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == appName:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + appName + " could not be found")
            return

        legitimateBots = self.cwaf.getLegitimateBots(id);
        self.cwaf.logout()
        return yaml.dump(legitimateBots)


    def bad_bots(self,appName):
        """Gets the list of observed bad bots for the application name provided"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == appName:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + appName + " could not be found")
            return


        badBots = self.cwaf.getBadBots(id);
        self.cwaf.logout()
        return yaml.dump(badBots)

    def search_engine_bots(self,appName):
        """Gets the list of search engine bots observed for the application name provided"""
        self.cwaf.login();
        apps = self.cwaf.getApplications();
        id = ''
        for app in apps['applications']:
            if app['applicationName'] == appName:
                id = app['applicationId']
                break
        if id == '':
            print("Error: application: " + appName + " could not be found")
            return

        searchEngineBots = self.cwaf.getSearchEngineBots(id);
        self.cwaf.logout()
        return yaml.dump(searchEngineBots)

    def activity_logs(self):
        self.cwaf.login()
        activityLogs=self.cwaf.getActivityLogs()
        self.cwaf.logout()
        return yaml.dump(activityLogs)

    def users(self):
        self.cwaf.login()
        users=self.cwaf.getUsers()
        self.cwaf.logout()
        return yaml.dump(users)

    def user(self,firstName,lastName):
        self.cwaf.login()
        users = self.cwaf.getUsers()
        for user in users:
            if user['firstName']==firstName and user['lastName']==lastName:
                return user
        self.cwaf.logout()
        return

class utils(object):

    def get_certificate_fingerprint(self):
        '''Returns a local certificate sha1 fingerprint for a cert.yaml file passed to stdin'''
        certs = yaml.load(sys.stdin, Loader=yaml.FullLoader)
        cert = load_certificate(FILETYPE_PEM, certs["certificate"])
        sha1_fingerprint = cert.digest("sha1")
        return sha1_fingerprint.decode("utf-8").replace(':','')


    def generate_yaml_cert_file(self,publicKeyFilePath,privateKeyFilePath,certChainFilePath="",passphase=""):
        cert={'cert':'','chain':'','key':'','passphase':passphase}

        publicKeyFile=open(publicKeyFilePath,'r')
        publicKey=publicKeyFile.read()
        cert['cert'] = publicKey

        privateKeyFile=open(privateKeyFilePath,'r')
        privateKey=privateKeyFile.read()
        cert['key']=privateKey

        if certChainFilePath != "":
            certChainFile = open(certChainFilePath, 'r')
            certChain = certChainFile.read()
            cert['chain'] = certChain

        yaml.dump(cert)




class Commands(object):

    def __init__(self):
        self.get=get()
        self.set=set()
        self.delete=delete()
        self.create=create()
        self.utils=utils()


if __name__ == '__main__':

  fire.Fire(Commands())