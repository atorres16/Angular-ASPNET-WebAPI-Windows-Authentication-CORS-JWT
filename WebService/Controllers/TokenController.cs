using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using WebApi.Jwt;

namespace WebService.Controllers
{
    public class TokenController : ApiController
    {
      
        //Windows auth required
        [Authorize]
        public string Get()
        {
            string user = User.Identity.Name;
            return JwtManager.GenerateToken(user);

        }

    }
}
