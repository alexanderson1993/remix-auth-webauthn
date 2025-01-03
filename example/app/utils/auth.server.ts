import { Authenticator } from "remix-auth";
import { WebAuthnStrategy } from "remix-auth-webauthn";
import {
  createAuthenticator,
  createUser,
  getAuthenticatorById,
  getAuthenticators,
  getUserById,
  getUserByUsername,
  User,
} from "~/utils/db.server";
import { userSession } from "~/utils/session.server";

export let authenticator = new Authenticator<User>();

export const webAuthnStrategy = new WebAuthnStrategy<User>(
  {
    // The React Router session storage where the "challenge" key is stored
    sessionStorage: userSession,
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
    getUserDetails: async (user) =>
      user ? { id: user.id, username: user.username } : null,
    // Find a user in the database with their username/email.
    getUserByUsername: (username) => getUserByUsername(username),
    getAuthenticatorById: (id) => getAuthenticatorById(id),
  },
  async function verify({ authenticator, type, username }) {
    let user: User | null = null;
    const savedAuthenticator = await getAuthenticatorById(authenticator.id);
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

authenticator.use(webAuthnStrategy, "webauthn");
