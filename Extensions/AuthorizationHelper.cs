using Microsoft.AspNetCore.Authorization;

namespace AspNetoCoreIdentity.Extension
{
    public class PermissaoNecessaria :IAuthorizationRequirement
    {
        public string Permissao { get; set; }

     public  PermissaoNecessaria(string permissao)
        {


            Permissao = permissao;

        }       

    }

    public class PermissaoNecessariaHandler : AuthorizationHandler<PermissaoNecessaria>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissaoNecessaria requirement)
        {
            if (context.User.HasClaim(c=>c.Type=="Permissao"&& c.Value.Contains(requirement.Permissao)))
            {

                context.Succeed(requirement);

            }

            return Task.CompletedTask;  
        }
    }
}
