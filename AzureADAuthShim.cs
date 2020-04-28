using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.SessionState;
using System.Web.UI.WebControls.WebParts;

namespace AzureADAuthModule
{
    public class AzureADAuthShim : System.Web.IHttpModule, IRequiresSessionState
    {
        private const string SessionVariableName = "AzureADAuthShim_Identity";
        private static string TenantId;
        private static string ClientId;
        private static string ClientSecret;
        private static string ADPropertyName;
        private static string LoginUrl;
        private static string HttpHeaderName;
        private static bool Initialized = false;
        private static readonly HttpClient client = new HttpClient();

        public void Dispose()
        {
            //clean up the httpclient
            client.Dispose();
        }

        public void Init(HttpApplication context)
        {
            //setup event handlers - prerequesthandlerexecute is async as we do web requests in that event.
            context.AddOnPreRequestHandlerExecuteAsync(new BeginEventHandler(this.BeginPreRequestHandlerExecute), new EndEventHandler(this.EndPreRequestHandlerExecute));
            //this handler is needed to ensure Session is available for our main event handler
            context.BeginRequest += Context_BeginRequest;
            //load settings from web.config/app settings
            EnsureInitialized();
        }

        private void Context_BeginRequest(object sender, EventArgs e)
        {
            //if we are handling the login calback, ensure session is writeable
            if (HttpContext.Current.Request.Url.ToString().StartsWith(LoginUrl))
            {
                HttpContext.Current.SetSessionStateBehavior(SessionStateBehavior.Required);
            }else
            {
                //if not, set to read only. THIS IS NECESSARY TO AVOID SESSION LOCKING
                HttpContext.Current.SetSessionStateBehavior(SessionStateBehavior.ReadOnly);
            }
        }

        //Wrapper function to enable async Task as IAsyncResult
        public IAsyncResult BeginPreRequestHandlerExecute(object sender, EventArgs e, AsyncCallback callback, object state)
        {
            var tcs = new TaskCompletionSource<object>(state);
            var task = Context_PreRequestHandlerExecuteAsync();
            task.ContinueWith(t =>
            {
                // Copy the task result into the returned task.
                if (t.IsFaulted)
                    tcs.TrySetException(t.Exception.InnerExceptions);
                else if (t.IsCanceled)
                    tcs.TrySetCanceled();
                else
                    tcs.TrySetResult(null);
                // Invoke the user callback if necessary.
                if (callback != null)
                    callback(tcs.Task);
            });
            return tcs.Task;
        }

        //this is probably unecessary but we'll follow the pattern...
        public void EndPreRequestHandlerExecute(IAsyncResult asyncResult)
        {
                return;   
        }

        private async Task Context_PreRequestHandlerExecuteAsync()
        {
            try
            {
                var context = HttpContext.Current;

                if (context.Session[SessionVariableName] != null)
                {
                    //we are already logged in with session variable set... ensure the header is applied and return;
                    SetHeaderFromSession();
                    return;
                }
                
                //we are not logged in, or we are on the receiving end of a login callback
                if (HttpContext.Current.Request.Url.ToString().StartsWith(LoginUrl))
                {
                    Debug.WriteLine("Handling login callback...");

                    //if "error" exists, check and log "error_description"
                    if (context.Request.QueryString["error"] != null)
                    {
                        var error = context.Request.QueryString["error"];
                        var errorDescription = context.Request.QueryString["error_description"];
                        throw new ApplicationException($"ADAzureAuthShim - Error logging user into Azure AD App login endpoint: {error}: {errorDescription}");
                    }

                    //check posted variable for code
                    if (HttpContext.Current.Request.QueryString["code"] != null)
                    {
                        string accessToken = await GetAccessToken();
                        JObject profile = await GetProfile(accessToken);


                        //get UPN and set in session
                        context.Session[SessionVariableName] = profile[ADPropertyName].Value<string>();
                        SetHeaderFromSession();

                        //redirect to "state"
                        context.Response.Redirect(HttpContext.Current.Request.QueryString["state"]);
                        context.Response.End();
                        return;

                    }
                    else
                    {
                        //error condition
                        throw new ApplicationException($"ADAzureAuthShim - Error handling login callback: 'code' not found in query string, and no error information was provided.");
                    }
                }
                else
                {
                    string redirectUri = HttpUtility.UrlEncode(HttpContext.Current.Request.Url.ToString());
                    //we are not logged in... redirect the user
                    context.Response.Redirect($"https://login.microsoftonline.com/{TenantId}/oauth2/v2.0/authorize?client_id={ClientId}&redirect_uri={LoginUrl}&response_type=code&response_mode=query&scope=openid&state={redirectUri}");
                    context.Response.Flush();
                    context.Response.End();
                    return;
                }
                
            }catch(Exception ex)
            {
                throw new ApplicationException($"ADAzureAuthShim - Error handling request", ex);
            }
        }

        private static void SetHeaderFromSession()
        {
            HttpContext.Current.Request.Headers[HttpHeaderName] = HttpContext.Current.Session[SessionVariableName].ToString();
        }

        private static async Task<JObject> GetProfile(string accessToken)
        {
            JObject profile;
            HttpResponseMessage response;
            client.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken}");
            response = await client.GetAsync("https://graph.microsoft.com/beta/me");
            client.DefaultRequestHeaders.Remove("Authorization");
            
            profile = JObject.Parse(await response.Content.ReadAsStringAsync());
            return profile;
        }

        private static async Task<string> GetAccessToken()
        {
            var values = new Dictionary<string, string>
                    {
                        {"client_id", ClientId},
                        {"client_secret",  ClientSecret},
                        {"scope", "openid" },
                        {"redirect_uri", LoginUrl },
                        {"code", HttpContext.Current.Request.QueryString["code"] },
                        {"grant_Type", "authorization_code" }
                    };

            var content = new FormUrlEncodedContent(values);
            HttpResponseMessage response;
            
            response = await client.PostAsync($"https://login.microsoftonline.com/{TenantId}/oauth2/v2.0/token", content);
            
            var sJSON = await response.Content.ReadAsStringAsync();
            JObject r = JObject.Parse(sJSON);
            string accessToken = r["access_token"].Value<string>();
            return accessToken;
        }

        private static void EnsureInitialized()
        {
            if (Initialized)
            {
                return;
            }
            else
            {
                //read config values from web.config
                TenantId = System.Configuration.ConfigurationManager.AppSettings["AAAS_TenantId"];
                ClientId = System.Configuration.ConfigurationManager.AppSettings["AAAS_ClientId"];
                ClientSecret = System.Configuration.ConfigurationManager.AppSettings["AAAS_ClientSecret"];
                ADPropertyName = System.Configuration.ConfigurationManager.AppSettings["AAAS_ADPropertyName"];
                HttpHeaderName = System.Configuration.ConfigurationManager.AppSettings["AAAS_HttpHeaderName"];
                LoginUrl = System.Configuration.ConfigurationManager.AppSettings["AAAS_LoginUrl"];

                Initialized = true;
            }
        }
    }
}
