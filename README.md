# WebAuthn Strategy - Remix Auth

Authenticate users with [Web Authentication](https://www.w3.org/TR/webauthn-2/) passkeys and physical tokens. It is implemented using [SimpleWebAuthn](https://simplewebauthn.dev) and supports user authentication and user registration using passkeys.

## Supported runtimes

| Runtime    | Has Support |
| ---------- | ----------- |
| Node.js    | ✅          |
| Cloudflare | ✅          |

<!-- If it doesn't support one runtime, explain here why -->

## About Web Authentication

Web Authentication lets a user register a device as a passkey. The device could be a USB device, like a Yubikey, the computer running the webpage, or a separate Bluetooth connected device like a smartphone. [This page has a good summary of the benefits](https://developer.apple.com/passkeys/), and you can [try it firsthand here](https://webauthn.io).

WebAuthn follows a two-step process. First, a device is _registered_ as a passkey. The browser generates a private/public key pair, associates it with a user ID and username, and sends the public key to the server to be verified. At this point the server could create a new user with that passkey, or if the user is already signed in the server could associate that passkey with the existing user.

In the _authentication_ step, the browser uses the passkey's private key to sign a challenge sent by the server, which the server checks with its stored public key in the verification step.

This strategy handles generating the challenge, storing it in session storage, passing the WebAuthn options to the client, generating the passkeys, and verifying the passkeys. Since this strategy requires database persistence and browser-based APIs, it requires a bit more work to set up.

> Note: This strategy also requires generating string user IDs on the browser. If your setup requires generating IDs, you might have to work around this limitation by creating a mapping of the authenticator userIds and your actual userIds.

## Setup

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
}
```

### Create the strategy instance

This strategy tries not to make assumptions about your database structure, so it requires several configuration options.

```ts
authenticator.use(
  new WebAuthnStrategy(
    {
      // The human-readable name of your app
      rpName: "Remix Auth WebAuthn",
      // The hostname of the website, determines where passkeys can be used
      // See https://www.w3.org/TR/webauthn-2/#relying-party-identifier
      rpID: env.NODE_ENV === "development" ? "localhost" : env.APP_URL,
      // Website URL (or array of URLs) where the registration can occur
      origin: env.APP_URL,
      // Return the list of authenticators associated with this user. You might
      // need to transform a CSV string into a list of strings at this step.
      getUserAuthenticators: async (user) => {
        const authenticators = await getAuthenticators(user)

        return authenticators.map((authenticator) => ({
          ...authenticator
          transports: authenticator.transports.split(",")
        }));
      },
      // Transform the user object into the shape expected by the strategy.
      // You can use a regular username, the users email address, or something else.
      getUserDetails: (user) => ({ id: user!.id, username: user!.email }),
      // Find a user in the database with their username/email.
      getUserByUsername: (username) => getUserByEmail(username),
    },
    async function verify({ authenticator, type, username }) {
     // ...
    }
  )
);
```

### Write your verify function

The verify function handles both the _registration_ and _authentication_ steps, and expects you to return a `user` object or throw an error if verification fails.

The verify function will receive an Authenticator object (without the userId), the provided username, and the type of verification - either `registration` or `authentication`.

Note: You'll have to implement your own endpoints for adding additional authenticators to existing users.

```ts
authenticator.use(
  new WebAuthnStrategy(
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
          user = await getUserByEmail(username);
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
  )
);
```

### Set up your login page loader and action

The login page will need a loader to supply the WebAuthn options from the server, and an action to deliver the passkey back to the server.

```ts
// /app/routes/_auth.login.ts
export let loader = async ({ request }: LoaderArgs) => {
  await authenticator.isAuthenticated(request, { successRedirect: "/" });

  // When we pass a GET request to the authenticator, it will
  // throw a response that includes the WebAuthn options and
  // stores the challenge on session storage. To avoid needing
  // a CatchBoundary, we catch the response here and return it as
  // loader data.
  try {
    await authenticator.authenticate("webauthn", request);
  } catch (response) {
    if (response instanceof Response && response.status === 200) {
      return response;
    }
    throw response;
  }
};

export let action = async ({ request }: DataFunctionArgs) => {
  // If you're using multiple authenticator strategies, you can
  // invoke them here based on the form data that was submitted.
  try {
    await authenticator.authenticate("webauthn", request, {
      successRedirect: "/",
    });
  } catch (error) {
    // You can catch the error here and resolve the message
    // for more direct error handling.
    if (error instanceof Response) {
      return { error: (await error.json()) as { message: string } };
    }
    throw error;
  }

  return null;
};
```

## Set up the form

For ease-of-use, this strategy provides a special Remix Form component that reads from `useLoaderData` and runs the browser-side Web Authentication functions in an `onSubmit` handler. It also includes a few required hidden form inputs. Take a look at the source code to see how its implemented. You should use this component in the same route that you defined your loader.

Your form should include a required `username` field and two buttons - one for registration and one for authentication.

```tsx
// /app/routes/_auth.login.ts
export default function Login() {
  let actionData = useActionData<Awaited<ReturnType<typeof action>>>();
  let navigationData = useNavigation();

  return (
    <WebAuthnForm>
      <label htmlFor="email">Email address</label>
      <input
        id="email"
        type="email"
        name="username"
        required
        placeholder="name@domain.com"
        autoComplete="webauthn username"
        disabled={Boolean(navigationData.state === "submitting")}
      />

      <button
        type="submit"
        value="registration"
        disabled={navigationData.state === "submitting"}
      >
        Sign Up with Passkey
      </button>
      <button
        type="submit"
        value="authentication"
        disabled={navigationData.state === "submitting"}
      >
        Sign In with Passkey
      </button>
      {actionData && "error" in actionData ? (
        <p className="text-red-600">{actionData.error?.message}</p>
      ) : null}
    </WebAuthnForm>
  );
}
```

## TODO

- Implement [Conditional UI](https://github.com/w3c/webauthn/wiki/Explainer:-WebAuthn-Conditional-UI)
