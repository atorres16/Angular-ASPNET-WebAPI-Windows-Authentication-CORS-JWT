using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using WebApi.Jwt.Filters;

namespace WebService.Controllers
{
    public class ItemsController : ApiController
    {
        
        [JwtAuthentication]
        public string Get()
        {
            return User.Identity.Name;
        }
    }
}
