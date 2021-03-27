using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AspNetMVC.AADAuthentications
{
    public partial class Startup
    {
        public const string CurrentUserSystemIdClaimType = "http://customclaimstype/currentUsersystemId";
        public const string CurrentUserYearIdClaimType = "http://customclaimstype/currentuseryearid";
        public const string TentantIdClaimType = "http://schemas.microsoft.com/identity/claims/tenantid";
        private static HashSet<string> _trustedTenantIds;
        private static bool? _checkForTrustedTenantId = null;
        private string ClientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private string Authority = EnsureTrailingSlash(ConfigurationManager.AppSettings["ida:AADInstance"]) + "common";

        internal static HashSet<string> TrustedTenantIds
        {
            get
            {
                if (_trustedTenantIds == null)
                {
                    string trustedTenantId = ConfigurationManager.AppSettings["TrustedTenantIds"];
                    _trustedTenantIds = string.IsNullOrWhiteSpace(trustedTenantId) ? new HashSet<string>()
                        : trustedTenantId.Split(';').ToHashSet();
                }

                return _trustedTenantIds;
            }
        }
        internal static bool CheckForTrustedTenantId
        {
            get
            {
                if (_checkForTrustedTenantId == null)
                {
                    bool checkForTrustedTenantId;
                    bool.TryParse(ConfigurationManager.AppSettings["CheckForTrustedTenantId"], out checkForTrustedTenantId);
                    _checkForTrustedTenantId = checkForTrustedTenantId;
                }

                return _checkForTrustedTenantId.Value;
            }
        }

        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions { });

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    ClientId = ClientId,
                    Authority = Authority,
                    TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                    {
                        // instead of using the default validation (validating against a single issuer value, as we do in line of business apps), 
                        // we inject our own multitenant validation logic
                        ValidateIssuer = false,
                        // If the app needs access to the entire organization, then add the logic
                        // of validating the Issuer here.
                        // IssuerValidator
                        //IssuerValidator = ValidateIssuer,                        
                    },
                    Notifications = new OpenIdConnectAuthenticationNotifications()
                    {
                        SecurityTokenValidated = (context) =>
                        {
                            CheckForTenantId(context.AuthenticationTicket.Identity);

                            //ToDo: Implement the bellow method to get any data you need from database
                            AddSystemClaims(context.AuthenticationTicket.Identity);
                            return Task.FromResult(0);
                        },
                        AuthenticationFailed = (context) =>
                        {
                            // Pass in the context back to the app
                            context.OwinContext.Response.Redirect("/Home/Error");
                            context.HandleResponse(); // Suppress the exception
                            return Task.FromResult(0);
                        },
                    }
                });
        }

        private string ValidateIssuer(string issuer
            , Microsoft.IdentityModel.Tokens.SecurityToken securityToken
            , Microsoft.IdentityModel.Tokens.TokenValidationParameters validationParameters)
        {
            if (string.IsNullOrWhiteSpace(issuer))
                throw new SecurityTokenValidationException($"Issuer Can't be null.");

            if (CheckForTrustedTenantId)
            {
                //ToDo: Add Issuer Check here.
                throw new SecurityTokenValidationException($"Issuer '{issuer}' is not trusted issuer.");
            }
            return issuer;
        }

        private static void CheckForTenantId(ClaimsIdentity claimsIdentity)
        {
            var tentantIdClaim = claimsIdentity.FindFirst(Startup.TentantIdClaimType);
            if(CheckForTrustedTenantId 
                && (tentantIdClaim == null || !TrustedTenantIds.Contains(tentantIdClaim.Value)))
                throw new SecurityTokenValidationException($"Tenant '{tentantIdClaim?.Value}' is not allowed to authenticate.");
        }
        
        private static void AddSystemClaims(ClaimsIdentity claimsIdentity)
        {
            //ToDo: Get any claims you need from the database
            //Then add any claims you need, the request must be very fast

            //ToDo: follow best practices to dispose the database connection by using "using" keyword.
            int systemId = 0;
            int yearId = 0;

            claimsIdentity.AddClaim(new System.Security.Claims.Claim(Startup.CurrentUserSystemIdClaimType, systemId.ToString(), ClaimValueTypes.Integer32));
            claimsIdentity.AddClaim(new System.Security.Claims.Claim(Startup.CurrentUserYearIdClaimType, yearId.ToString(), ClaimValueTypes.Integer32));
        }

        private static string EnsureTrailingSlash(string value)
        {
            if (value == null)
            {
                value = string.Empty;
            }

            if (!value.EndsWith("/", StringComparison.Ordinal))
            {
                return value + "/";
            }

            return value;
        }
    }
}
