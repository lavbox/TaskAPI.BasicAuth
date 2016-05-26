using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http.Filters;

namespace SecureTaskAPI.Filters
{
    public class BasicAuthenticationFilter : Attribute, IAuthenticationFilter
    {
        public virtual bool AllowMultiple
        {
            get { return false; }
        }

        public Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            HttpRequestMessage request = context.Request;
            AuthenticationHeaderValue authorization = request.Headers.Authorization;
            string realmName = "TaskAPI";
            
            if (authorization == null)
            {
                // No authentication was attempted (for this authentication method).
               return Task.FromResult(1);
            }

            if (authorization.Scheme != "Basic")
            {
                // Authentication scheme is not Basic
                return Task.FromResult(1);
            }

            if (String.IsNullOrEmpty(authorization.Parameter))
            {
                // Authentication was attempted but failed. Set ErrorResult to indicate an error.
                context.ErrorResult = new System.Web.Http.Results.UnauthorizedResult(new List<AuthenticationHeaderValue> { GetChallengeHeader(realmName) }, context.Request);
                return Task.FromResult(1);
            }

            Tuple<string, string> userNameAndPasword = ExtractUserNameAndPassword(authorization.Parameter);

            if (userNameAndPasword == null)
            {
                // Authentication was attempted but failed. Set ErrorResult to indicate an error.
                context.ErrorResult = new System.Web.Http.Results.UnauthorizedResult(new List<AuthenticationHeaderValue> { GetChallengeHeader(realmName) }, context.Request);
                return Task.FromResult(1);
            }

            IPrincipal principal = Validate(userNameAndPasword);

            if (principal == null)
            {
                // Authentication was attempted but failed. Set ErrorResult to indicate an error.
                context.ErrorResult = new System.Web.Http.Results.UnauthorizedResult(new List<AuthenticationHeaderValue> { GetChallengeHeader(realmName) }, context.Request);
            }
            else
            {
                // Authentication was attempted and succeeded. Set Principal to the authenticated user.
                context.Principal = principal;
            }
            return Task.FromResult(1);
        }

        private IPrincipal Validate(Tuple<string,string> credential)
        {
            string userName = credential.Item1;
            string password = credential.Item2;
            if (userName != ConfigurationManager.AppSettings["Basic_Auth_Username"] || password != ConfigurationManager.AppSettings["Basic_Auth_Password"])
            {
                // No user with userName/password exists.
                return null;
            }

            // Create a ClaimsIdentity with all the claims for this user.
            Claim nameClaim = new Claim(ClaimTypes.Name, userName);
            List<Claim> claims = new List<Claim> { nameClaim };

            // important to set the identity this way, otherwise IsAuthenticated will be false
            ClaimsIdentity identity = new ClaimsIdentity(claims,"Basic");

            var principal = new ClaimsPrincipal(identity);
            return principal;
        }

        private static Tuple<string, string> ExtractUserNameAndPassword(string authorizationParameter)
        {
            byte[] credentialBytes;

            try
            {
                credentialBytes = Convert.FromBase64String(authorizationParameter);
            }
            catch (FormatException)
            {
                return null;
            }

            string decodedCredentials;

            try
            {
                decodedCredentials = Encoding.ASCII.GetString(credentialBytes);
            }
            catch (DecoderFallbackException)
            {
                return null;
            }

            if (String.IsNullOrEmpty(decodedCredentials))
            {
                return null;
            }

            int colonIndex = decodedCredentials.IndexOf(':');

            if (colonIndex == -1)
            {
                return null;
            }

            string userName = decodedCredentials.Substring(0, colonIndex);
            string password = decodedCredentials.Substring(colonIndex + 1);
            return new Tuple<string, string>(userName, password);
        }

        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(HttpContext.Current.User.Identity.Name))
            {
                string realmName = "TaskAPI";
                AuthenticationHeaderValue header = GetChallengeHeader(realmName);
                context.Result = new System.Web.Http.Results.UnauthorizedResult(new List<AuthenticationHeaderValue> { header }, context.Request);
            }
            return Task.FromResult(0);
        }

        private static AuthenticationHeaderValue GetChallengeHeader(string realmName)
        {
            string parameter = "realm=\""+ realmName+"\"";
            AuthenticationHeaderValue header = new AuthenticationHeaderValue("Basic", parameter);
            return header;
        }
    }
}