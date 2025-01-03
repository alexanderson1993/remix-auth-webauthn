# Changelog

## 0.5.0

This is a *BREAKING CHANGE*.

- Upgrade to Remix Auth 4.0.0, which provides support for React Router v7.
- The `getUserAuthenticators`, `getUserDetails`, `getUserByUsername`, and `getAuthenticatorById` methods passed to the `WebAuthnStrategy` constructor are now required to be async functions that return a promise.
- `WebAuthnStrategy` now requires a React Router `sessionStorage` object to be passed to the constructor to store the challenge string.
- For better compatibility with SimpleWebAuthn v10, the optional `generateUserId` config option passed to `handleFormSubmit` must now return a Uint8Array with a length of 32 or 64. If not passed, the library with automatically generate a secure ID.
- Added a new example app which demonstrates how the library is to be used.

## 0.4.0

This is a *BREAKING CHANGE*.

## 0.3.0

This is a *BREAKING CHANGE*.

- Upgrade to SimpleWebAuthn v10, which requires Node v20 TLS. Make sure you upgrade to Node 20 before using this package.
- `webAuthnStrategy.generateOptions` no longer returns `json` data, to better support Single Fetch. You'll need to manually store the challenge in the session or some other storage.

```ts
// /app/routes/_auth.login.ts
export async function loader({ request, response }: LoaderFunctionArgs) {
  const user = await authenticator.isAuthenticated(request);
  let session = await sessionStorage.getSession(
    request.headers.get("Cookie")
  );

  const options = webAuthnStrategy.generateOptions(request, user);

  // Set the challenge in a session cookie so it can be accessed later.
  session.set("challenge", options.challenge)
  
  // Update the cookie
  response.headers.append("Set-Cookie", await sessionStorage.commitSession(session))
  response.headers.set("Cache-Control":"no-store")

  return options;
}
```

## 0.2.1

This is a *BREAKING CHANGE*.

- Instead of exporting the server and browser modules from `remix-auth-webauthn`, they've been given separate imports: `remix-auth-webauthn/server` and `remix-auth-webauthn/browser`.

```diff
// /app/auth.server.ts
- import { WebAuthnStrategy } from "remix-auth-webauthn";
+ import { WebAuthnStrategy } from "remix-auth-webauthn/server";
```

```diff
- import { handleFormSubmit } from "remix-auth-webauthn";
+ import { handleFormSubmit } from "remix-auth-webauthn/browser";
```

This should remove the need for including `remix-auth-webauthn` or the `@simplewebauthn` packages in your `serverDependenciesToBundle` list.
