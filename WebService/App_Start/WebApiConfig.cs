using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Web.Http;
using System.Web.Http.Cors;

namespace WebService
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            config.Formatters.JsonFormatter.SupportedMediaTypes.Add(new MediaTypeHeaderValue("text/html"));
            config.Formatters.JsonFormatter.SerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore;
            config.Formatters.JsonFormatter.SerializerSettings.PreserveReferencesHandling = Newtonsoft.Json.PreserveReferencesHandling.None;

            // Web API configuration and services
            config.Filters.Add(new AuthorizeAttribute());

            // Web API routes
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );

            // Web API configuration and services
            //EnableCorsAttribute cors = new EnableCorsAttribute("http://localhost:4200,http://localhost,*", "Accept, Origin, Content-Type, X-Auth-Token, cache-control, x-requested-with", "GET, POST ,PATCH, PUT, DELETE, OPTIONS");
            
            EnableCorsAttribute cors = new EnableCorsAttribute("*", "Accept, Authorization, Origin, Content-Type, X-Auth-Token, cache-control, x-requested-with", "GET, POST ,PATCH, PUT, DELETE, OPTIONS");

            cors.SupportsCredentials = true;
            config.EnableCors(cors);
        }
    }
}
