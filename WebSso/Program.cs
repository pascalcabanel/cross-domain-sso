using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.HttpOverrides;
using System;
using WebSso.Components;

namespace WebSso
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            var keycloakSettings = builder.Configuration.GetSection("KeyCloak");
            var authority = keycloakSettings["realm"];
            var clientId = keycloakSettings["ClientId"];
            var clientSecret = keycloakSettings["ClientSecret"];
            var baseUri = Environment.GetEnvironmentVariable("base-uri");

            // Add authentication services
            builder.Services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie(options =>
            {
                options.Cookie.Name = "WebSsoAuthCookie";
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.None;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.ExpireTimeSpan = TimeSpan.FromDays(7); // Cookie validity duration
                options.SlidingExpiration = true;              // Extends the duration with each request

                options.Events = new CookieAuthenticationEvents
                {
                    OnSigningIn = context =>
                    {
                        context.Properties.IsPersistent = true; // ← crucial for a persistent cookie
                        return Task.CompletedTask;
                    }
                };

            })
            .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
            {
                options.Authority = authority;
                options.ClientId = clientId;
                options.ClientSecret = clientSecret;
                options.ResponseType = "code";
                options.SaveTokens = true;
                options.GetClaimsFromUserInfoEndpoint = true;
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("email");
                options.CallbackPath = "/signin-oidc";
                options.Events = new OpenIdConnectEvents
                {
                    OnRedirectToIdentityProvider = context =>
                    {
                        context.ProtocolMessage.RedirectUri = $"{baseUri}/signin-oidc";
                        return Task.CompletedTask;
                    },

                    // SignOut event
                    OnRedirectToIdentityProviderForSignOut = async context =>
                    {
                        var idToken = await context.HttpContext.GetTokenAsync("id_token");

                        if (string.IsNullOrEmpty(idToken))
                        {
                            throw new InvalidOperationException("Impossible de récupérer l'id_token nécessaire pour la déconnexion SSO.");
                        }

                        var logoutUri = $"{context.Options.Authority}/protocol/openid-connect/logout" +
                                        $"?id_token_hint={idToken}" +
                                        $"&post_logout_redirect_uri={Uri.EscapeDataString(context.Options.SignedOutRedirectUri)}";

                        context.Response.Redirect(logoutUri);
                        context.HandleResponse(); // ← avoids default behavior
                    },

                    // Redirection after return from Keycloak SignOut
                    OnSignedOutCallbackRedirect = context =>
                    {
                        context.Response.Redirect("/logout-success"); // or another URL of your choice
                        context.HandleResponse();
                        return Task.CompletedTask;
                    }
                };
            });
            
            if (string.IsNullOrEmpty(baseUri))
            {
                baseUri = "https://localhost:7068"; // ← to test in development environment
            }
            builder.Services.AddScoped(sp => new HttpClient
            {
                BaseAddress = new Uri(baseUri)
            });

            builder.Services.AddAuthorization();
            builder.Services.AddRazorComponents().AddInteractiveServerComponents();
            builder.Services.AddHttpContextAccessor();
            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Error");
                app.UseHsts();
            }

            app.UseStaticFiles();

            // Required when running the application behind a reverse proxy like Nginx.
            // This enables ASP.NET Core to correctly process the X-Forwarded-For and X-Forwarded-Proto headers,
            // which represent the original client IP address and the original protocol (http/https), respectively.
            // This is essential for proper handling of redirects, authentication, logging, etc.
            // ⚠️ Warning: In production, it's strongly recommended to explicitly specify allowed proxy IPs
            // using KnownProxies or KnownNetworks to prevent header spoofing vulnerabilities.

            app.UseForwardedHeaders(new ForwardedHeadersOptions
            {
                ForwardedHeaders = ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedFor,
                RequireHeaderSymmetry = false,
                ForwardLimit = null,
                KnownNetworks = { }, // allows all networks (do not keep in production)
                KnownProxies = { } // allows all proxies (do not keep in production)
            });

            app.UseRouting();

            // To log the requests in the console
            app.Use(async (context, next) =>
            {
                Console.WriteLine($"➡️ Requête entrante : {context.Request.Method} {context.Request.Path}");
                await next();
            });

            app.UseAuthentication();

            // Custom middleware to validate the Keycloak session on the root path ("/").
            // If the user is authenticated, it retrieves the access_token and sends a request
            // to the Keycloak /userinfo endpoint to verify the token's validity.
            // If the token is invalid or the session has expired on the Keycloak side,
            // the user is signed out and redirected to the home page.
            // This ensures session consistency between the ASP.NET Core app and the Keycloak server.
            // ⚠️ Note: This check only applies to the "/" path — consider expanding it if needed for broader coverage.
            // Also, calling the userinfo endpoint on every request may have performance implications.

            app.Use(async (context, next) =>
            {
                if (context.Request.Path == "/" && context.User.Identity?.IsAuthenticated == true)
                {
                    var accessToken = await context.GetTokenAsync("access_token");

                    if (!string.IsNullOrEmpty(accessToken))
                    {
                        var httpClient = new HttpClient();
                        var authority = builder.Configuration.GetSection("KeyCloak")["realm"];
                        var userInfoEndpoint = $"{authority}/protocol/openid-connect/userinfo";

                        var request = new HttpRequestMessage(HttpMethod.Get, userInfoEndpoint);
                        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

                        try
                        {
                            var response = await httpClient.SendAsync(request);
                            if (!response.IsSuccessStatusCode)
                            {
                                // Token invalide ou session expirée : déconnexion
                                await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                                context.Response.Redirect("/");
                                return;
                            }
                        }
                        catch (Exception ex)
                        {
                            // Gestion des erreurs de communication avec Keycloak
                            Console.WriteLine($"Erreur lors de la vérification de la session Keycloak : {ex.Message}");
                            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                            context.Response.Redirect("/");
                            return;
                        }
                    }
                }

                await next();
            });

            app.UseAuthorization();

            // Endpoint to handle user logout via Keycloak using OpenID Connect.
            // This route is protected and only accessible to authenticated users.

            app.MapGet("/api/logout", async (HttpContext context) =>
            {
                Console.WriteLine("👋 Déconnexion de l'utilisateur...");
                if (!context.User.Identity?.IsAuthenticated ?? true)
                {
                    return Results.BadRequest("Utilisateur non authentifié.");
                }

                var idToken = await context.GetTokenAsync("id_token");

                if (string.IsNullOrEmpty(idToken))
                {
                    return Results.BadRequest("Token manquant.");
                }

                var logoutUri = Environment.GetEnvironmentVariable("signout-callback");
                if (string.IsNullOrEmpty(logoutUri))
                {
                    logoutUri = $"{context.Request.Scheme}://{context.Request.Host}/signout-callback-oidc";
                }
                var authority = context.RequestServices
                    .GetRequiredService<IConfiguration>()
                    .GetSection("KeyCloak")["realm"];

                var keycloakLogout = $"{authority}/protocol/openid-connect/logout" +
                                     $"?id_token_hint={idToken}" +
                                     $"&post_logout_redirect_uri={Uri.EscapeDataString(logoutUri)}";
                
                Console.WriteLine($"👋  SignOut request with redirect on {logoutUri}");

                await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                await context.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);

                return Results.Redirect(keycloakLogout);
            }).RequireAuthorization();

            app.UseAntiforgery();

            app.MapRazorComponents<App>()
                .AddInteractiveServerRenderMode();

            app.Run();
        }
    }
}
