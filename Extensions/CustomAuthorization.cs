using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Security.Claims;

namespace AspNetoCoreIdentity.Extension
{
    public class CustomAuthorization
    {
        public static bool ValidarClaimUsuario(HttpContext context, string claimName, string claimValue)
        {

            return context.User.Identity.IsAuthenticated &&
                   context.User.Claims.Any(c => c.Type == claimName && c.Value.Contains(claimValue));

        }
    }
        public class ClaimsAuthorizeAtribute : TypeFilterAttribute
        {
            public ClaimsAuthorizeAtribute(string claimName ,string claimType) :base(typeof(RequisitoClaimFilter))
            {
                Arguments = new object[] {new Claim(claimName,claimType)};

            }
        }

        public class RequisitoClaimFilter : IAuthorizationFilter
        {

            readonly Claim _claim;

            public RequisitoClaimFilter(Claim claim)
            {

                _claim = claim;

            }

            public void OnAuthorization(AuthorizationFilterContext context)
            {
            if (!context.HttpContext.User.Identity.IsAuthenticated)
            {

                context.Result = new RedirectToRouteResult(new RouteValueDictionary(new { area = "Identity", page = "/Account/Login", ReturnUrl = context.HttpContext.Request.Path.ToString() }));


            }


                if (!CustomAuthorization.ValidarClaimUsuario(context.HttpContext,_claim.Type,_claim.Value))
                {

                    context.Result = new StatusCodeResult(403);

                }
            }
        }
    }
