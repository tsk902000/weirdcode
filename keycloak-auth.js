// This authentication script can be used to authenticate in a webapplication via forms.
// The submit target for the form, the name of the username field, the name of the password field
// and, optionally, any extra POST Data fields need to be specified after loading the script.
// The username and the password need to be configured when creating any Users.

// The authenticate function is called whenever ZAP requires to authenticate, for a Context for which this script
// was selected as the Authentication Method. The function should send any messages that are required to do the authentication
// and should return a message with an authenticated response so the calling method.
//
// NOTE: Any message sent in the function should be obtained using the 'helper.prepareMessage()' method.
//
// Parameters:
//        helper - a helper class providing useful methods: prepareMessage(), sendAndReceive(msg)
//      paramsValues - the values of the parameters configured in the Session Properties -> Authentication panel.
//                  The paramsValues is a map, having as keys the parameters names (as returned by the getRequiredParamsNames()
//                  and getOptionalParamsNames() functions below)
//      credentials - an object containing the credentials values, as configured in the Session Properties -> Users panel.
//                  The credential values can be obtained via calls to the getParam(paramName) method. The param names are the ones
//                  returned by the getCredentialsParamsNames() below
var ScriptVars = Java.type('org.zaproxy.zap.extension.script.ScriptVars');

function obtainKeycloakToken() {

    var HttpRequestHeader = Java.type("org.parosproxy.paros.network.HttpRequestHeader");
    var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
    var HttpSender = Java.type('org.parosproxy.paros.network.HttpSender');
    var HttpMessage = Java.type('org.parosproxy.paros.network.HttpMessage');
    var msg = new HttpMessage(new HttpRequestHeader(HttpHeader.POST, paramsValues.get("KeycloakURL"), HttpRequestHeader.HTTP10));

    var body = 'client_id=' + encodeURIComponent(paramsValues.get("ClientId")) +
               '&username=' + encodeURIComponent(paramsValues.get("Username")) +
               '&password=' + encodeURIComponent(paramsValues.get("Password")) +
               '&grant_type=password' +
               '&scope=roles';

    msg.setRequestBody(body);
    msg.getRequestHeader().setHeader(HttpRequestHeader.CONTENT_TYPE, 'application/x-www-form-urlencoded');
    msg.getRequestHeader().setContentLength(msg.getRequestBody().length());

    var sender = new HttpSender(Model.getSingleton().getOptionsParam().getConnectionParam(), true, HttpSender.MANUAL_REQUEST_INITIATOR);
    sender.sendAndReceive(msg);

    var responseBody = msg.getResponseBody().toString();
    var jsonResponse = JSON.parse(responseBody);
    print("Received response status code: " + responseBody);
    return jsonResponse.access_token;
}

function authenticate(helper, paramsValues, credentials) {
    print("Authenticating via JavaScript script...");

    var token = ScriptVars.getGlobalVar('keycloak.token1');

    if (!token) {
        var msg1 = helper.prepareMessage();
        token = obtainKeycloakToken();
        ScriptVars.setGlobalVar('keycloak.token1', token);
    }

    var requestUri = new URI(helper.getURI());
    var msg = helper.prepareMessage();

    msg.getRequestHeader().setHeader('Authorization', 'Bearer ' + token);
    msg.getRequestHeader().setHeader('Content-Type', 'application/json');

    return msg;
}

// This function is called during the script loading to obtain a list of the names of the required configuration parameters,
// that will be shown in the Session Properties -> Authentication panel for configuration. They can be used
// to input dynamic data into the script, from the user interface (e.g. a login URL, name of POST parameters etc.)
function getRequiredParamsNames(){
    return ["KeycloakURL", "ClientId","Username", "Password"];
}

// This function is called during the script loading to obtain a list of the names of the optional configuration parameters,
// that will be shown in the Session Properties -> Authentication panel for configuration. They can be used
// to input dynamic data into the script, from the user interface (e.g. a login URL, name of POST parameters etc.)
function getOptionalParamsNames(){
    return [];
}

// This function is called during the script loading to obtain a list of the names of the parameters that are required,
// as credentials, for each User configured corresponding to an Authentication using this script 
function getCredentialsParamsNames(){
    return ["Username", "Password"];
}