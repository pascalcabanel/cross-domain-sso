
# 🧠 Proof of Concept – Authentification SSO multi-domaines avec Keycloak

## 🎯 Objectif du projet

Ce projet a pour but de démontrer la mise en œuvre d’une **authentification centralisée (SSO)** entre deux applications (`www.mondomaine.fr` et `www.mondomaine.com`) à l’aide de **Keycloak** et du protocole **OpenID Connect (OIDC)**.

L’ensemble fonctionne en environnement Docker avec un **reverse proxy Nginx** en frontal pour la gestion des certificats HTTPS générés localement avec `mkcert`.

---

## 🏗️ Architecture globale

```
 Utilisateur ⇄ Nginx ⇄ [mondomaine.fr (Docker)]
               ⇓
              Keycloak
               ⇑
 ⇄ Nginx ⇄ [mondomaine.com (Docker)]
```

- **mondomaine.fr** et **mondomaine.com** sont des applications .NET 9 hébergées dans Docker.
- **Keycloak** est utilisé comme fournisseur OIDC.
- **Nginx** gère le HTTPS avec des certificats générés localement.

---

## 🔧 Étapes de mise en œuvre

### 1. Création des certificats SSL

```bash
mkcert -install
mkcert -cert-file mondomaine.fr.pem -key-file mondomaine.fr-key.pem www.mondomaine.fr
mkcert -cert-file mondomaine.com.pem -key-file mondomaine.com-key.pem www.mondomaine.com
```

### 2. Ajout de la racine de certificat dans Windows

```bash
certutil -addstore -f "Root" rootCA.pem
```

> Cela permet à Chrome et à Windows de faire confiance aux certificats locaux.

### 3. Configuration Nginx

#### Exemple pour `www.mondomaine.fr`

```nginx
server {
    listen 443 ssl;
    server_name www.mondomaine.fr;

    ssl_certificate /etc/nginx/certs/mondomaine.fr.pem;
    ssl_certificate_key /etc/nginx/certs/mondomaine.fr-key.pem;

    location / {
        proxy_pass http://192.168.1.53:8888;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Même principe pour `www.mondomaine.com` avec port `8889`.

### 4. Docker Compose

```yaml
services:
  mondomaine-fr:
    image: websso
    build:
      context: .
      dockerfile: WebSso/Dockerfile
    environment:
      - ASPNETCORE_ENVIRONMENT=Development
      - ASPNETCORE_URLS=http://+:8080
    ports:
      - "8888:8080"

  mondomaine-com:
    image: websso
    build:
      context: .
      dockerfile: WebSso/Dockerfile
    environment:
      - ASPNETCORE_ENVIRONMENT=Development
      - ASPNETCORE_URLS=http://+:8080
    ports:
      - "8889:8080"
```

### 5. Configuration Keycloak

Dans le client OIDC Keycloak (`test-client`) :

- **Valid redirect URIs** :  
  `https://www.mondomaine.fr/signin-oidc`  
  `https://www.mondomaine.com/signin-oidc`

- **Valid post logout redirect URIs** :  
  `https://www.mondomaine.fr/logout-success`  
  `https://www.mondomaine.com/logout-success`

- **Web Origins** : `*` ou chaque domaine explicitement

---

## ⚙️ Configuration de l’application .NET (extrait `Program.cs`)

```csharp
options.Events = new OpenIdConnectEvents
{
    OnRedirectToIdentityProviderForSignOut = async context =>
    {
        var idToken = await context.HttpContext.GetTokenAsync("id_token");
        var logoutUri = $"{context.Options.Authority}/protocol/openid-connect/logout" +
                        $"?id_token_hint={idToken}" +
                        $"&post_logout_redirect_uri={Uri.EscapeDataString(context.Options.SignedOutRedirectUri)}";

        context.Response.Redirect(logoutUri);
        context.HandleResponse();
    },
    OnSignedOutCallbackRedirect = context =>
    {
        context.Response.Redirect("/logout-success");
        context.HandleResponse();
        return Task.CompletedTask;
    }
};
```

### 🔐 Authentification

- Système d’authentification basé sur cookie persistant
- Utilisation des events `OnRedirectToIdentityProvider`, `OnSignedOutCallbackRedirect`, etc.
- Vérification des tokens OIDC et récupération des claims utilisateurs

---

## 🔍 Résultat observé

| Action                       | Résultat attendu                             |
|-----------------------------|----------------------------------------------|
| Accès à mondomaine.fr       | Redirection vers Keycloak                    |
| Connexion                   | Session active sur mondomaine.fr ET .com     |
| Déconnexion                 | Session détruite sur les deux domaines       |
| Cookie persistant           | Géré par le middleware cookie                |

---

## ⚠️ Points de vigilance

- `SameSite=None` requis dans les cookies pour SSO inter-domaines
- HTTPS **obligatoire** pour `openid-connect`
- `mkcert` génère un certificat auto-signé → pas adapté en production
- Ne pas oublier d’importer les **deux certificats** côté Windows si tests locaux

---

## ✅ Conclusion

Ce POC valide la possibilité d’une **authentification unique multi-domaines** avec Keycloak. Il sert de base solide pour intégrer une **IAM** centralisée dans un système microservices ou multi-applications.

