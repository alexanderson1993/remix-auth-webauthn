# Changelog

## 0.3.0

This is a *BREAKING CHANGE*.

- Upgrade to SimpleWebAuthn v10, which requires Node v20 TLS. Make sure you upgrade to Node 20 before using this package.

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
