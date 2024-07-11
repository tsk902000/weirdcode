var HttpSender = Java.type("org.parosproxy.paros.network.HttpSender");
var ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");

function sendingRequest(msg, initiator, helper) {
  // add Authorization header to all request in scope except the authorization request itself
  if (initiator !== HttpSender.AUTHENTICATION_INITIATOR && msg.isInScope()) {
    msg
      .getRequestHeader()
      .setHeader(
        "Authorization",
        "Bearer " + ScriptVars.getGlobalVar("access_token")
      );
  }
}

function responseReceived(msg, initiator, helper) {}