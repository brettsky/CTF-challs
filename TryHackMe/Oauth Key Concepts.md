This task will discuss the key concepts for understanding OAuth, specifically OAuth 2.0. These concepts form the foundation for understanding how the OAuth 2.0 framework was built. As a pentester or a secure coder, it is essential to understand these concepts to pentest a website or write code without a vulnerability. **To make these concepts more relatable, we will explain them through a daily routine example: using a coffee shop's mobile app to order and pay for coffee.**

**[[Resource Owner]]**: person or system that controls certain ddata and can authorize and application to access data on their behalf. IE: as a customer you control what information you give to the coffee shop.

**Client**: what you interact with. Web app,moblie app 

**Authorization Server** Responsible for issuing access tokens to the client This server ensures that only authenticated and authorized clients can access or manipulate the resource owner's data

**Resource Server** The server hosting the protected resources. IE account information. Order history, payment details, 

**Authorization grant**: What is given after login that allows the client to get an access token The primary grant types are `Authorization Code`, `Implicit`, `Resource Owner Password Credentials`, and `Client Credentials`
**Access token**: A cred that is used to access protected resources on behalf of the resource owner. 

**Refresh Token** A cred that is used to obtain a new access token Preventing repeat logins after an access token expires  (Typically 1 hour - some are longer ~24 some are even shorter 5-10 mins)

**Redirect URI** The URI to which the authorization server will redirect the resource owner after auth is granted or denied. It checks  if the client for which the authorization response has been requested is correct

**Scope** mechanism for limiting an applications access to a user account Scopes help enforce the [[principle of least privilege]]

**State Parameter**: Optional parameter maintains the [[state]] between the client and authorization server. Crucial part of securing the OAuth flow

**Token and Authorization End point** - The authorization server's endpoint is where the client exchanges the authorization grant (or refresh token) for an access token. In contrast, the authorization endpoint is where the resource owner is authenticated and authorizes the client to access the protected resources.

