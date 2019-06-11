#!/bin/env python
import os
import base64
import logging
import requests
import json

# Custom logger
_log = logging.getLogger(__name__)


class AuthParams():
    """
    Class to manage authorization parameters or authorization headers
    """
    authHeader = ''
    authParams = ''

    def __init__(self, authMode, fgAPIs):
        if authMode == fgAPIs.AuthModes['NONE']:
            pass
        elif authMode == fgAPIs.AuthModes['PTV']:
            self.authHeader = "Bearer " + fgAPIs.ptvToken
        elif authMode == fgAPIs.AuthModes['BASELINE_TOKEN']:
            self.authHeader = fgAPIs.baselineToken
        elif authMode == fgAPIs.AuthModes['BASELINE_PARAMS']:
            self.authParams = "username=" + fgAPIs.fgUser +\
                              "&password=" + fgAPIs.fgB64Password
        else:
            pass

    def isAuthParams(self):
        return len(self.authParams) > 0

    def isAuthHeader(self):
        return len(self.authHeader) > 0

    def getAuthParams(self):
        return self.authParams

    def getAuthHeader(self):
        return self.authHeader


class FutureGatewayAPIs():
    """
    FutureGatewayAPIs Constructor
    """
    fgBaseUrl = 'http://localhost/fgapiserver'
    fgAPIVersion = 'v1.0'
    fgUser = 'futuregateway'
    fgPassword = 'futuregateway'
    fgB64Password = None
    ptvToken = None
    baselineToken = None
    errFlag = False
    errMessage = None
    errRequest = None
    LS = os.linesep

    AuthModes = {
        'NONE': 'NONE',                      # No authentication at all
        'PTV': 'PTV',                        # Heder: 'Authorization: Bearer <token>'
        'BASELINE_TOKEN': 'BASELINE_TOKEN',  # Header: 'Authorization: <token>'
        'BASELINE_PARAMS': 'BASELINE_PARAMS' # Parameters: username=<user>&password=<password>
    }
    currentAuth = 'NONE'

    def __init__(self, *args, **dargs):
        if(len(args) > 0):
            self.fgBaseUrl = args[0]
            self.fgAPIVersion = args[1]
            self.fgUser = args[2]
            self.fgPassword = args[3]
        if(dargs is not None):
            self.fgBaseUrl = dargs.get('base_url', self.fgBaseUrl)
            self.fgAPIVersion = dargs.get('api_version', self.fgAPIVersion)
            self.fgUser = dargs.get('fg_user', self.fgUser)
            self.fgPassword = dargs.get('fg_password', self.fgPassword)
        self.fgB64Password = base64.b64encode(self.fgPassword)
        self.ptvToken = ''
        self.baselineToken = ''
        self.errFlag = False
        _log.debug('Created FutureGatewayAPIs: \'%s\'' % self)

    def __str__(self):
        """
        Represent this class and its status
        """
        return "Base URL: '" + str(self.fgBaseUrl) + "'" + self.LS +\
               "API Version: '" + str(self.fgAPIVersion) + "'" + self.LS +\
               "User: '" + str(self.fgUser) + "'" + self.LS +\
               "Password: '" + str(self.fgPassword) + "'" + self.LS +\
               "PasswordB64Encoded: '" + str(self.fgB64Password) + "'" + self.LS +\
               "PTV Token: '" + str(self.ptvToken) + "'" + self.LS +\
               "Baseline Token: '" + str(self.baselineToken) + "'" + self.LS +\
               "Authentication mode: '" + str(self.currentAuth) + "'" + self.LS +\
               "Error" + self.LS +\
               "  Flag: '" + str(self.errFlag) + "'" +self.LS +\
               "  Request: '" + str(self.errRequest) + "'" +self.LS +\
               "  Message: '" + str(self.errMessage) + "'" + self.LS

    def __repr__(self):
        """
        Print out this class and its status
        """
        print(self)

    def setAuthMode(self, mode):
        """
        Verify if the server responds and check APIs version match
        """
        _log.debug("setAuthMode(%s)" % mode)
        self.currentAuth = mode

    def checkServer(self):
        """
        Set a new baselineToken with the given accessToken
        this method is useful to switch between user and
        delegated tokens
        """
        _log.debug("checkServer")
        json = self.doGet("");
        return not self.errFlag

    def setBaselineToken(self, accessToken):
        _log.debug("setBaselineToken(%s)" % accessToken)
        self.baselineToken = accessToken

    def setPTVToken(self, ptvToken):
        """
        Set PTV token
        """
        _log.debug("setPTVToken(%s)" % ptvToken)
        self.ptvToken = ptvToken

    def getAccessToken(self, username, userdel):
        """
        Get user baseline access token, if a delegated user is specified
        the method returns the delegated token and class member baselineToken 
        will be updated accordingly
        """
        _log.debug("getAccessToken(%s, %s)" % (username, userdel))
        # Endpoint auth/ is the only one requiring BASELINE_PARAMS credentials
        # Current Auth value will be switched to this mode during this method
        # Previous authentication mode will be restored to its original value
        # after method execution
        prevAuth = self.currentAuth
        self.currentAuth = self.AuthModes['BASELINE_PARAMS']
        self.baselineToken = ''
        delegatedUserParam = ''
        if userdel is not None and len(userdel) > 0:
            delegatedUserParam = "?user=" + userdel;
        json = self.doGet("auth" + delegatedUserParam);
        if(not self.errFlag):
            if userdel is not None and len(userdel) > 0:
                self.baselineToken = json.get('delegated_token', None)
            else:
                self.baselineToken = json.get('token', None)
            if len(self.baselineToken) == 0:
                self.errFlag = True;
                self.errMessage = "Empty token retrieved for user: '" + username + "'";
        self.currentAuth = prevAuth;
        _log.debug("baselineToken: '" + self.baselineToken + "'");
        return self.baselineToken;

    def userExists(self, username):
        """
        Verify if the specified user exists
        """
        _log.debug('userExists(%s)' % username)
        jsonResult = self.doGet('users/' + username)
        return not self.errFlag and jsonResult.get('name',None) == username

    def createUser(self,
                   name,
                   firstName,
                   lastName,
                   mail,
                   institute):
        """
        Create a FutureGateway user
        """
        _log.debug("createUser(%s, %s, %s, %s, %s)"
                   % (name, firstName, lastName, mail, institute));
        data = {'first_name': firstName,
                'last_name': lastName,
                'mail': mail,
                'institute': institute}
        _log.debug('jsonData: %s' % data)
        jsonResult = self.doPost('users/%s' % name, data)
        if self.errFlag is True:
            errMessage = "Unable to create json object from json data: '%s'" % jsonData
            _log.error(self.errMessage)
        return not self.errFlag

    def addUserGroups(self, userName, userGroups):
        """
        Add a given list of groups to a given user
        """
        _log.debug("addUserGroups")
        data = { 'groups': userGroups}
        _log.debug("jsonData: '" + jsonData + "'");
        jsonResult = self.doPost("users/" + userName + "/groups", data)
        if self.errFlag is True:
            errMessage = "Unable to add groups: '%s'" % (userGroups, userName)
        return not self.errFlag

    def deleteUserGroups(self, userName, userGroups):
        """
        Delete a given list of groups to a given user
        """
        _log.debug("removeUserGroups");
        data = { 'groups': userGroups }
        _log.debug("jsonData: '" + jsonData + "'");
        jsonResult = self.doDelete("users/" + userName + "/groups", data)
        if self.errFlag is True:
            errMessage = "Unable to remove groups: '%s' to user: '%s'" % (userGroups, userName)
            _log.error(errMessage)
        return not self.errFlag;

    def getUserGroups(self, userName):
        """
        Return the list groups assigned to a specified user
        """
        _log.debug("getUserGroups");
        jsonResult = self.doGet("users/" + userName + "/groups")
        if jsonResult is not None:
            groups = jsonResult.get("groups", None)
        return groups

    def userHasGroup(self, userName, groupName):
        """
        Return true if the specified user has the specified group
        """
        _log.debug("userHasGroup")
        groups = self.getUserGroups(userName)
        if(groups != null):
            for group in groups:
                if group['name'] == groupName:
                    return True
        return False

    def setError(self, request, errorDetail):
        self.errFlag = True;
        self.errMessage = errorDetail;
        self.errRequest = request;

    def initFGRequest(self, endpoint, authParams):
        """
        Perform common operations before intitating a FutureGateway API request
        """
        textRequest = ''
        # Reset err variables
        self.errFlag = False;
        self.errMessage = "";
        self.errRequest = textRequest = self.fgBaseUrl + "/" +\
                                        self.fgAPIVersion + "/" + endpoint
        if(authParams.isAuthParams()):
            try:
                textRequest.index("?")
                textRequest += "&" + authParams.getAuthParams()
            except ValueError:
                textRequest += "?" + authParams.getAuthParams()
        _log.debug("Request: '" + textRequest + "'")
        return textRequest;

    def doGet(self, endpoint):
        """
        Perform a GET request to a given futuregateway API endpoint
        """
        jsonResult = ''
        authParams = AuthParams(self.currentAuth, self)
        fgTextRequest = self.initFGRequest(endpoint, authParams)
        _log.debug("GET (request: %s)" % fgTextRequest)
        #Prepare and execute the GET request
        headers = {'Cache-Control': 'no-cache'}
        if(authParams.isAuthHeader() is True):
            headers['Authorization'] = authParams.getAuthHeader()
            _log.debug("Authorization: " + authParams.getAuthHeader())
        try:
            r = requests.get(url=fgTextRequest,
                             headers=headers)
            jsonResult = r.json()
        except requests.exceptions.RequestException as e:
            self.setError(fgTextRequest, e)
        _log.debug("GET (result: '%s')" % jsonResult)
        return jsonResult

    def doPost(self, endpoint, data):
        """
        Perform a POST request to a given futuregateway API endpoint
        """
        jsonResult = ''
        authParams = AuthParams(self.currentAuth, self)
        fgTextRequest = self.initFGRequest(endpoint, authParams)
        _log.debug("POST (request: %s)" % fgTextRequest)
        #Prepare and execute the GET request
        headers = {'Cache-Control': 'no-cache',
                   'Content-Type': 'application/json; charset=UTF-8'}
        if(authParams.isAuthHeader() is True):
            headers['Authorization'] = authParams.getAuthHeader()
            _log.debug("Authorization: " + authParams.getAuthHeader())
        try:
            r = requests.post(url=fgTextRequest,
                              headers=headers,
                              data=json.dumps(data))
            print("POST", fgTextRequest, headers, json.dumps(data), r.text)
            jsonResult = r.json()
        except requests.exceptions.RequestException as e:
            self.setError(fgTextRequest, e)
        _log.debug("POST (result: '%s')" % jsonResult)
        return jsonResult

    def doDelete(self, endpoint, data):
        """
        Perform a DELETE request to a given futuregateway API endpoint
        """
        jsonResult = ''
        authParams = AuthParams(self.currentAuth, self)
        fgTextRequest = self.initFGRequest(endpoint, authParams)
        _log.debug("DELETE (request: %s)" % fgTextRequest)
        #Prepare and execute the GET request
        headers = {'Cache-Control': 'no-cache',
                   'Content-Type': 'application/json; charset=UTF-8'}
        if(authParams.isAuthHeader() is True):
            headers['Authorization'] = authParams.getAuthHeader()
            _log.debug("Authorization: " + authParams.getAuthHeader())
        try:
            r = requests.delete(url=fgTextRequest,
                                headers=headers,
                                data=json.dumps(data))
            jsonResult = r.json()
        except requests.exceptions.RequestException as e:
            self.setError(fgTextRequest, e)
        _log.debug("DELETE (result: '%s')" % jsonResult)
        return jsonResult

if __name__ == '__main__':
    fgBaseUrl = 'http://localhost/fgapiserver'
    fgAPIVer = 'v1.0'
    fgUser = 'futuregateway'
    fgPassword = 'futuregateway'
    fgAPIs = FutureGatewayAPIs(
        fgBaseUrl,
        fgAPIVer,
        fgUser,
        fgPassword)
    authParams = AuthParams('NONE', fgAPIs)
    checkResult = fgAPIs.checkServer()
    print("Server at: %s, is connecting: %s" % (fgAPIs.errRequest, checkResult))
    suAccessToken = fgAPIs.getAccessToken(fgUser, None)
    print("SU access token: %s" % suAccessToken)
    fgAPIs.setAuthMode(fgAPIs.AuthModes['BASELINE_TOKEN'])

    # Portal user case
    # Pay attention when a new user is provided providing an exiting mail address, it will cause an http 500
    screenName = 'portalUser'
    firstName = 'portalUserFirstName'
    lastName = 'portalUserLastName'
    emailAddress = 'portal@user.mail.address'

    userExists = fgAPIs.userExists(screenName)
    print("User: '%s' exists is: %s" % (screenName, userExists))
    if not userExists:
        fgAPIs.createUser(screenName,
                          firstName,
                          lastName,
                          emailAddress,
                          "")
        # Check if the inserted user now exists
        userExists = fgAPIs.userExists(screenName);
        print("Now user: '%s' exists is: %s" % (screenName, userExists))

    if userExists:
        delegatedAccessToken = fgAPIs.getAccessToken(fgUser, screenName)
        print("User '%s' access token: %s" % (fgUser, delegatedAccessToken))


