using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.SessionState;

namespace AzureADAuthModule
{
    public class AzureADAuthShim : System.Web.IHttpModule, IRequiresSessionState
    {
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

        }

        public void Init(HttpApplication context)
        {
            // context.BeginRequest += Context_BeginRequest;
            context.PreRequestHandlerExecute += Context_PreRequestHandlerExecute;
            context.BeginRequest += Context_BeginRequest1;
            EnsureInitialized();
        }

        private void Context_BeginRequest1(object sender, EventArgs e)
        {
            if (HttpContext.Current.Request.Url.ToString().StartsWith(LoginUrl))
            {
                HttpContext.Current.SetSessionStateBehavior(SessionStateBehavior.Required);
            }else
            {
                HttpContext.Current.SetSessionStateBehavior(SessionStateBehavior.ReadOnly);
            }
        }

        private void Context_PreRequestHandlerExecute(object sender, EventArgs e)
        {
            if (HttpContext.Current.Session["AzureADAuthShim_Identity"] != null)
            {
                HttpContext.Current.Request.Headers[HttpHeaderName] = HttpContext.Current.Session["AzureADAuthShim_Identity"].ToString();
            }
            else
            {
                //we are not logged in, or we are on the receiving end of a login callback
                if (HttpContext.Current.Request.Url.ToString().StartsWith(LoginUrl))
                {
                    Debug.WriteLine("Coming back from login...");

                    //if "error" exists, check and log "error_description"

                    //check posted variable for code
                    if (HttpContext.Current.Request.QueryString["code"] != null)
                    {
                        string accessToken = GetAccessToken();
                        /*string jwtClaims = accessToken.Split(new char[] { '.' })[1];

                        //this is dumb, but...
                        while (jwtClaims.Length % 4 != 0)
                        {
                            jwtClaims += "=";
                        }

                        JObject claims = JObject.Parse(System.Text.UnicodeEncoding.UTF8.GetString(System.Convert.FromBase64String(jwtClaims)));
                        string upn = claims[ADPropertyName].Value<string>();
                        */

                        JObject profile;
                        HttpResponseMessage response;
                        lock (client)
                        {
                            client.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken}");
                            response = client.GetAsync("https://graph.microsoft.com/beta/me").GetAwaiter().GetResult();
                            client.DefaultRequestHeaders.Remove("Authorization");
                        }
                        profile = JObject.Parse(response.Content.ReadAsStringAsync().GetAwaiter().GetResult());


                        //get UPN and set in session
                        HttpContext.Current.Session["AzureADAuthShim_Identity"] = profile[ADPropertyName].Value<string>();
                        HttpContext.Current.Request.Headers.Add(HttpHeaderName, HttpContext.Current.Session["AzureADAuthShim_Identity"].ToString());

                        //redirect to "state"
                        HttpContext.Current.Response.Redirect(HttpContext.Current.Request.QueryString["state"]);
                        HttpContext.Current.Response.End();

                    }
                    else
                    {
                        //error condition
                    }
                }
                else
                {
                    string redirectUri = HttpUtility.UrlEncode(HttpContext.Current.Request.Url.ToString());
                    //we are not logged in... redirect the user
                    HttpContext.Current.Response.Redirect($"https://login.microsoftonline.com/{TenantId}/oauth2/v2.0/authorize?client_id={ClientId}&redirect_uri={LoginUrl}&response_type=code&response_mode=query&scope=openid&state={redirectUri}");
                    HttpContext.Current.Response.Flush();
                    HttpContext.Current.Response.End();
                }
            }
        }

        private static string GetAccessToken()
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
            lock (client)
            {
                response = client.PostAsync($"https://login.microsoftonline.com/{TenantId}/oauth2/v2.0/token", content).GetAwaiter().GetResult();
            }
            var sJSON = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            JObject r = JObject.Parse(sJSON);
            string accessToken = r["access_token"].Value<string>();
            return accessToken;
        }

        private void EnsureInitialized()
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

                Debug.WriteLine("Initialized from webconfig...");
                Initialized = true;
            }
        }
    }
}
