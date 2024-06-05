# WebAuthn Strategy - Remix Auth

Authenticate users with [Web Authentication](https://www.w3.org/TR/webauthn-2/) passkeys and physical tokens. It is implemented using [SimpleWebAuthn](https://simplewebauthn.dev) and supports user authentication and user registration using passkeys.

> This package should be considered unstable. It works in my limited testing, but I haven't covered every case or written automated tests. _Caveat emptor_.

## Supported runtimes

| Runtime    | Has Support |
| ---------- | ----------- |
| Node.js    | ✅          |
| Cloudflare | ❓          |

> I haven't tested it in a Cloudflare environment. If you do, let me know how it goes!

<!-- If it doesn't support one runtime, explain here why -->

> This package also only supports ESM, because package.json is scary and I'm not certain how to set up the necessary build steps. You might need to add this to your `serverDependenciesToBundle` in your remix.config.js file.

## About Web Authentication

Web Authentication lets a user register a device as a passkey. The device could be a USB device, like a Yubikey, the computer running the webpage, or a separate Bluetooth connected device like a smartphone. [This page has a good summary of the benefits](https://developer.apple.com/passkeys/), and you can [try it firsthand here](https://webauthn.io).

WebAuthn follows a two-step process. First, a device is _registered_ as a passkey. The browser generates a private/public key pair, associates it with a user ID and username, and sends the public key to the server to be verified. At this point the server could create a new user with that passkey, or if the user is already signed in the server could associate that passkey with the existing user.

In the _authentication_ step, the browser uses the passkey's private key to sign a challenge sent by the server, which the server checks with its stored public key in the verification step.

This strategy handles generating the challenge, storing it in session storage, passing the WebAuthn options to the client, generating the passkeys, and verifying the passkeys. Since this strategy requires database persistence and browser-based APIs, it requires a bit more work to set up.

> Note: This strategy also requires generating string user IDs on the browser. If your setup requires generating IDs, you might have to work around this limitation by creating a mapping of the authenticator userIds and your actual userIds.

## Setup

### Install

This project depends on `remix-auth`. Install it and [follow the setup instructions](https://github.com/sergiodxa/remix-auth).

```
npm install remix-auth remix-auth-webauthn
```

### Database

This strategy requires database access to store user Authenticators. The kind of database doesn't matter, but the strategy expects authenticators to match this interface (as provided by @simplewebauthn/server):

```ts
interface Authenticator {
  // SQL: Encode to base64url then store as `TEXT` or a large `VARCHAR(511)`. Index this column
  credentialID: string;
  // Some reference to the user object. Consider indexing this column too
  userId: string;
  // SQL: Encode to base64url and store as `TEXT`
  credentialPublicKey: string;
  // SQL: Consider `BIGINT` since some authenticators return atomic timestamps as counters
  counter: number;
  // SQL: `VARCHAR(32)` or similar, longest possible value is currently 12 characters
  // Ex: 'singleDevice' | 'multiDevice'
  credentialDeviceType: string;
  // SQL: `BOOL` or whatever similar type is supported
  credentialBackedUp: boolean;
  // SQL: `VARCHAR(255)` and store string array or a CSV string
  // Ex: ['usb' | 'ble' | 'nfc' | 'internal']
  transports: string;
  // SQL: `VARCHAR(36)` or similar, since AAGUIDs are 36 characters in length
  aaguid: string;
}
```

If you're just playing around, you can use this stub in-memory database.

<details>
<summary>Show Code</summary>

```ts
// /app/db.server.ts
import { type Authenticator } from "remix-auth-webauthn/server";

export type User = { id: string; username: string };

const authenticators = new Map<string, Authenticator>();
const users = new Map<string, User>();
export function getAuthenticatorById(id: string) {
  return authenticators.get(id) || null;
}
export function getAuthenticators(user: User | null) {
  if (!user) return [];

  const userAuthenticators: Authenticator[] = [];
  authenticators.forEach((authenticator) => {
    if (authenticator.userId === user.id) {
      userAuthenticators.push(authenticator);
    }
  });

  return userAuthenticators;
}
export function getUserByUsername(username: string) {
  users.forEach((user) => {
    if (user.username === username) {
      return user;
    }
  });
  return null;
}
export function getUserById(id: string) {
  return users.get(id) || null;
}
export function createAuthenticator(
  authenticator: Omit<Authenticator, "userId">,
  userId: string
) {
  authenticators.set(authenticator.credentialID, { ...authenticator, userId });
}
export function createUser(username: string) {
  const user = { id: Math.random().toString(36), username };
  users.set(user.id, user);
  return user;
}
```

> Note that this database will reset every time your server restarts, but any passkeys you generate will still be present on your device. You'll have to manually delete them.

</details>

### Create the strategy instance

This strategy tries not to make assumptions about your database structure, so it requires several configuration options. Also, to give you access to the methods on the WebAuthnStrategy instance, create and export it before passing it to `authenticator.use`.

```ts
// /app/authenticator.server.ts
import { WebAuthnStrategy } from "remix-auth-webauthn/server";
import {
  getAuthenticators,
  getUserByUsername,
  getAuthenticatorById,
  type User,
  createUser,
  createAuthenticator,
  getUserById,
} from "./db";
import { Authenticator } from "remix-auth";
import { sessionStorage } from "./session.server";

export let authenticator = new Authenticator<User>(sessionStorage);

export const webAuthnStrategy = new WebAuthnStrategy<User>(
  {
    // The human-readable name of your app
    // Type: string | (response:Response) => Promise<string> | string
    rpName: "Remix Auth WebAuthn",
    // The hostname of the website, determines where passkeys can be used
    // See https://www.w3.org/TR/webauthn-2/#relying-party-identifier
    // Type: string | (response:Response) => Promise<string> | string
    rpID: (request) => new URL(request.url).hostname,
    // Website URL (or array of URLs) where the registration can occur
    origin: (request) => new URL(request.url).origin,
    // Return the list of authenticators associated with this user. You might
    // need to transform a CSV string into a list of strings at this step.
    getUserAuthenticators: async (user) => {
      const authenticators = await getAuthenticators(user);

      return authenticators.map((authenticator) => ({
        ...authenticator,
        transports: authenticator.transports.split(","),
      }));
    },
    // Transform the user object into the shape expected by the strategy.
    // You can use a regular username, the users email address, or something else.
    getUserDetails: (user) =>
      user ? { id: user.id, username: user.username } : null,
    // Find a user in the database with their username/email.
    getUserByUsername: (username) => getUserByUsername(username),
    getAuthenticatorById: (id) => getAuthenticatorById(id),
  },
  async function verify({ authenticator, type, username }) {
    // Verify Implementation Here
  }
);

authenticator.use(webAuthnStrategy);
```

### Write your verify function

The verify function handles both the _registration_ and _authentication_ steps, and expects you to return a `user` object or throw an error if verification fails.

The verify function will receive an Authenticator object (without the userId), the provided username, and the type of verification - either `registration` or `authentication`.

Note: It should be possible to expand this to support giving a single user multiple passkeys by checking to see if the user is already logged in.

```ts
const webAuthnStrategy = new WebAuthnStrategy(
  {
    // Options here...
  },
  async function verify({ authenticator, type, username }) {
    let user: User | null = null;
    const savedAuthenticator = await getAuthenticatorById(
      authenticator.credentialID
    );
    if (type === "registration") {
      // Check if the authenticator exists in the database
      if (savedAuthenticator) {
        throw new Error("Authenticator has already been registered.");
      } else {
        // Username is null for authentication verification,
        // but required for registration verification.
        // It is unlikely this error will ever be thrown,
        // but it helps with the TypeScript checking
        if (!username) throw new Error("Username is required.");
        user = await getUserByUsername(username);

        // Don't allow someone to register a passkey for
        // someone elses account.
        if (user) throw new Error("User already exists.");

        // Create a new user and authenticator
        user = await createUser(username);
        await createAuthenticator(authenticator, user.id);
      }
    } else if (type === "authentication") {
      if (!savedAuthenticator) throw new Error("Authenticator not found");
      user = await getUserById(savedAuthenticator.userId);
    }

    if (!user) throw new Error("User not found");
    return user;
  }
);
```

### Set up your login page loader and action

The login page will need a loader to supply the WebAuthn options from the server, and an action to deliver the passkey back to the server.

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

export async function action({ request }: ActionFunctionArgs) {
  try {
    await authenticator.authenticate("webauthn", request, {
      successRedirect: "/",
    });
    return { error: null };
  } catch (error) {
    // This allows us to return errors to the page without triggering the error boundary.
    if (error instanceof Response && error.status >= 400) {
      return { error: (await error.json()) as { message: string } };
    }
    throw error;
  }
}
```

If you choose to store the challenge somewhere other than session storage, such as in a database, you can pass it as context to the authenticate function in your action.

```ts
export async function action({ request }: ActionFunctionArgs) {
  const challenge = await getChallenge(request);
  try {
    await authenticator.authenticate("webauthn", request, {
      successRedirect: "/",
      context: { challenge },
    });
    return { error: null };
  } catch (error) {
    // This allows us to return errors to the page without triggering the error boundary.
    if (error instanceof Response && error.status >= 400) {
      return { error: (await error.json()) as { message: string } };
    }
    throw error;
  }
}
```

## Set up the form

For ease-of-use, this strategy provides an `onSubmit` handler which performs the necessary browser-side actions to generate passkeys. The `onSubmit` handler is generated by passing in the options object from the loader above. Depending on your setup, you might need to implement separate forms for registration and authentication.

When registering, the process follows a few steps:

1. When first visiting the login page, the server will provide an options object which can be used for both registration and authentication.
2. The user requests registration by entering their desired username and pressing the "Check Username" button, which submits a GET request to get updated options.
3. The server responds with whether the username is taken and if the user already has registered a passkey so the browser doesn't produce duplicates.
4. The form must be submitted a second time, as POST this time, with the actual passkey for registration.
5. The server verifies the passkey, creates the new user, and logs the user in.

Your registration form should include a required `username` field and `<button name="intent" value="registration">` for triggering registration. You can use `formMethod="GET"` on a submit button to submit the value of the `username` field to the loader to check if the username is available. The `registration` button should change state and behavior based on whether the options from the loader indicate that the username is available. This is demonstrated below.

Authentication is a simpler process and only requires one button press:

1. The user requests authentication, and the browser shows the available passkeys for the domain.
2. The user picks a passkey, and the form is generated and submitted to the server.
3. The server verifies the passkey by checking it against the database, and logs the user in.

Since the username is stored with the passkey in the browser, the `username` field is not required for the authentication form, but you should include a submit button like so: `<button name="intent" value="authentication">` to trigger the authentication flow.

Here's what the forms might look like in practice:

```tsx
// /app/routes/_auth.login.ts
import { handleFormSubmit } from "remix-auth-webauthn/browser";

export default function Login() {
  const options = useLoaderData<typeof loader>();
  const actionData = useActionData<typeof action>();
  return (
    <Form onSubmit={handleFormSubmit(options)} method="POST">
      <label>
        Username
        <input type="text" name="username" />
      </label>
      <button formMethod="GET">Check Username</button>
      <button
        name="intent"
        value="registration"
        disabled={options.usernameAvailable !== true}
      >
        Register
      </button>
      <button name="intent" value="authentication">
        Authenticate
      </button>
      {actionData?.error ? <div>{actionData.error.message}</div> : null}
    </Form>
  );
}
```

You can set the [`attestationType`](https://simplewebauthn.dev/docs/packages/server#1a-supported-attestation-formats) in the second parameter of `handleFormSubmit`. If omitted, it defaults to `none`:

```tsx
onSubmit={handleFormSubmit(options, { attestationType: "direct" })}
```

## Displaying passkeys to the user

An important part of supporting passkeys in your app is allowing your users to manage their passkeys on a settings page or similar. Users should be able to see a list of their passkeys, delete passkeys from your database, and register new passkeys.

You can use the `getUserAuthenticators` function on the strategy instance to get a list of passkeys associated with the user:

```tsx
// /app/routes/settings.tsx
export async function loader({ request }: LoaderFunctionArgs) {
  const user = await authenticator.isAuthenticated(request);
  if (!user) {
    return redirect("/login");
  }

  const authenticators = await webAuthnStrategy.getUserAuthenticators(user);

  return json({ authenticators });
};

export default function Settings() {
  const data = useLoaderData();

  return (
    <ul>
      {data.authenticators.map((authenticator) => (
        ...
      ))}
    </ul>
  );
}
```

When listing passkeys, it's also helpful to display the name of the device that registered the passkey to the user so they can distinguish between them (especially when they have multiple passkeys registered). To accomplish this, you can use the community-sourced list available in the [passkey-authenticator-aaguids](https://github.com/passkeydeveloper/passkey-authenticator-aaguids) repository to match each authenticator's `aaguid` to its registering device and display the name (and even a brand icon) to the user.

To learn more about best practices for passkey management, refer to Google's [Passkeys user journeys](https://developers.google.com/identity/passkeys/ux/user-journeys) guide.

## TODO

- Implement [Conditional UI](https://github.com/w3c/webauthn/wiki/Explainer:-WebAuthn-Conditional-UI)

```

```
