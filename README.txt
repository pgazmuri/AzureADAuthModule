This proof-of-concept module will enforce login to an AD application, validating the returned login code and extracting a single property from the claims and applying that property to a header on the inbound request.
The intent is to replace existing ISAPI-based functionality provided by other authentication tools (such as Siteminder).

To configure, create an AzureAD web app that supports implicit grant with id_token (in the portal, browse to your app -> authentication -> add platform), and include the necessary claim on the access token. (In the portal, browse to your app -> Token Configuration -> Add CLaim -> Access Token)

To deploy this httpModule, ensure the following items are defined in your web.config, and include this .dll in the /bin folder

WebConfig changes:

  <appSettings>
    <add key="AAAS_TenantId" value="<tenant name, guid or common>" />
    <add key="AAAS_ClientId" value="<App ID>" />
    <add key="AAAS_ClientSecret" value="<client secret>" />
    <add key="AAAS_ADPropertyName" value="upn" />
    <add key="AAAS_HttpHeaderName" value="SMUser" />
    <add key="AAAS_LoginUrl" value="https://localhost:44349/?loginCallback" />
  </appSettings>
  <system.webServer>
    <validation validateIntegratedModeConfiguration="false"/>
    <modules>
      <add name="AzureADAuthShim" type="AzureADAuthModule.AzureADAuthShim,AzureADAuthModule" />
    </modules>
  </system.webServer>


Note that this module requires session state, so you may also need something like the following config:
  <system.webServer>
    <modules>
      <remove name="Session" />
      <add name="Session" type="System.Web.SessionState.SessionStateModule" preCondition="" />
      <add name="AzureADAuthShim" type="AzureADAuthModule.AzureADAuthShim,AzureADAuthModule" />
    </modules>
  </system.webServer>
  <system.web>
    <sessionState mode="InProc" />
    ...
  </system.web>

NOTE: This module is not production ready and is a proof-of-concept only.  It should be updated with the following to be minimally viable in production:

Add logging / telemetry
