import {
  json,
  SessionStorage,
  type SessionData,
} from "@remix-run/server-runtime";
import {
  AuthenticateOptions,
  Strategy,
  StrategyVerifyCallback,
} from "remix-auth";
import {
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  PublicKeyCredentialDescriptorJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/typescript-types";

interface WebAuthnAuthenticator {
  credentialID: string;
  transports: string[];
}

export interface Authenticator {
  credentialID: string;
  userId: string;
  credentialPublicKey: string;
  counter: number;
  credentialDeviceType: string;
  credentialBackedUp: number;
  transports: string;
}

export interface UserDetails {
  id: string;
  username: string;
  displayName?: string;
}

export interface WebAuthnOptionsResponse {
  usernameAvailable: boolean | null;
  rp: {
    name: string;
    id: string;
  };
  user: {
    id: string;
    username: string;
    displayName: string;
  } | null;
  challenge: string;
  authenticators: PublicKeyCredentialDescriptorJSON[];
}

/**
 * This interface declares what configuration the strategy needs from the
 * developer to correctly work.
 */
export interface WebAuthnOptions<User> {
  /**
   * Relaying Party name - The human-readable name of your app
   */
  rpName: string;
  /**
   * Relaying Party ID -The hostname of the website, determines where passkeys can be used
   * @link https://www.w3.org/TR/webauthn-2/#relying-party-identifier
   */
  rpID: string;
  /**
   * Website URL (or array of URLs) where the registration can occur
   */
  origin: string | string[];
  /**
   * Return a list of authenticators associated with the user.
   * @param user object
   * @returns Authenticator
   */
  getUserAuthenticators: (
    user: User | null
  ) => Promise<WebAuthnAuthenticator[]> | WebAuthnAuthenticator[];
  /**
   * Transform the user object into the shape expected by the strategy.
   * You can use a regular username, the users email address, or something else.
   * @param user object
   * @returns UserDetails
   */
  getUserDetails: (
    user: User | null
  ) => Promise<UserDetails | null> | UserDetails | null;
  /**
   * Find a user in the database with their username/email.
   * @param username
   * @returns User object
   */
  getUserByUsername: (username: string) => Promise<User | null> | User | null;
  /**
   * Find an authenticator in the database by its credential ID
   * @param id
   * @returns Authenticator
   */
  getAuthenticatorById: (
    id: string
  ) => Promise<Authenticator | null> | Authenticator | null;
}

/**
 * This interface declares what the developer will receive from the strategy
 * to verify the user identity in their system.
 */
export type WebAuthnVerifyParams = {
  authenticator: Omit<Authenticator, "userId">;
  type: "registration" | "authentication";
  username: string | null;
};

export class WebAuthnStrategy<User> extends Strategy<
  User,
  WebAuthnVerifyParams
> {
  name = "webauthn";

  rpName: string;
  rpID: string;
  origin: string | string[];
  getUserAuthenticators: (
    user: User | null
  ) => Promise<WebAuthnAuthenticator[]> | WebAuthnAuthenticator[];
  getUserDetails: (
    user: User | null
  ) => Promise<UserDetails | null> | UserDetails | null;
  getUserByUsername: (username: string) => Promise<User | null> | User | null;
  getAuthenticatorById: (
    id: string
  ) => Promise<Authenticator | null> | Authenticator | null;

  constructor(
    options: WebAuthnOptions<User>,
    verify: StrategyVerifyCallback<User, WebAuthnVerifyParams>
  ) {
    super(verify);
    this.rpName = options.rpName;
    this.rpID = options.rpID;
    this.origin = options.origin;
    this.getUserAuthenticators = options.getUserAuthenticators;
    this.getUserDetails = options.getUserDetails;
    this.getUserByUsername = options.getUserByUsername;
    this.getAuthenticatorById = options.getAuthenticatorById;
  }

  async authenticate(
    request: Request,
    sessionStorage: SessionStorage<SessionData, SessionData>,
    options: AuthenticateOptions
  ): Promise<User> {
    let session = await sessionStorage.getSession(
      request.headers.get("Cookie")
    );
    try {
      let user: User | null = session.get(options.sessionKey) ?? null;

      // User is already authenticated
      if (user && request.method === "POST") {
        return this.success(user, request, sessionStorage, options);
      }

      if (request.method === "GET") {
        let authenticators: WebAuthnAuthenticator[] = [];
        let userDetails: UserDetails | null = null;
        let usernameAvailable: boolean | null = null;
        if (!user) {
          const username = new URL(request.url).searchParams.get("username");
          if (username) {
            usernameAvailable = true;
            user = await this.getUserByUsername(username || "");
          }
        }

        if (user) {
          authenticators = await this.getUserAuthenticators(user);
          userDetails = await this.getUserDetails(user);
          usernameAvailable = false;
        }

        const crypto = await import("tiny-webcrypto");
        const options: WebAuthnOptionsResponse = {
          usernameAvailable,
          rp: { name: this.rpName, id: this.rpID },
          user: userDetails
            ? { displayName: userDetails.username, ...userDetails }
            : null,
          challenge: Buffer.from(
            crypto.default.getRandomValues(new Uint8Array(32))
          ).toString("base64url"),
          authenticators: authenticators.map(
            ({ credentialID, transports }) => ({
              id: credentialID,
              type: "public-key",
              transports: transports as AuthenticatorTransportFuture[],
            })
          ),
        };

        session.set("challenge", options.challenge);

        throw json(options, {
          status: 200,
          headers: {
            "Set-Cookie": await sessionStorage.commitSession(session),
            "Cache-Control": "no-store",
          },
        });
      }

      if (request.method !== "POST")
        throw new Error(
          "Only use the WebAuthn authenticate with POST or GET requests."
        );

      const expectedChallenge = session.get("challenge");

      // Based on the authenticator response, either verify registration,
      // or verify authentication
      const formData = await request.formData();
      let data: unknown;
      try {
        const responseData = formData.get("response");
        if (typeof responseData !== "string") throw new Error("Error");
        data = JSON.parse(responseData);
      } catch {
        throw new Error("Invalid passkey response JSON.");
      }
      const type = formData.get("type");
      let username = formData.get("username");
      if (typeof username !== "string") username = null;
      if (type === "registration") {
        if (!username) throw new Error("Username is a required form value.");
        const verification = await verifyRegistrationResponse({
          response: data as RegistrationResponseJSON,
          expectedChallenge,
          expectedOrigin: this.origin,
          expectedRPID: this.rpID,
        });

        if (verification.verified && verification.registrationInfo) {
          const {
            credentialPublicKey,
            credentialID,
            counter,
            credentialBackedUp,
            credentialDeviceType,
          } = verification.registrationInfo;

          const newAuthenticator = {
            credentialID: Buffer.from(credentialID).toString("base64url"),
            credentialPublicKey:
              Buffer.from(credentialPublicKey).toString("base64url"),
            counter,
            credentialBackedUp: credentialBackedUp ? 1 : 0,
            credentialDeviceType,
            transports: "",
          };

          user = await this.verify({
            authenticator: newAuthenticator,
            type: "registration",
            username,
          });
        } else {
          throw new Error("Passkey verification failed.");
        }
      } else if (type === "authentication") {
        const authenticationData = data as AuthenticationResponseJSON;
        const authenticator = await this.getAuthenticatorById(
          authenticationData.id
        );
        if (!authenticator) throw new Error("Passkey not found.");

        const verification = await verifyAuthenticationResponse({
          response: authenticationData,
          expectedChallenge,
          expectedOrigin: this.origin,
          expectedRPID: this.rpID,
          authenticator: {
            ...authenticator,
            credentialPublicKey: Buffer.from(
              authenticator.credentialPublicKey,
              "base64url"
            ),
            credentialID: Buffer.from(authenticator.credentialID, "base64url"),
            transports: authenticator.transports.split(
              ","
            ) as AuthenticatorTransportFuture[],
          },
        });

        if (!verification.verified)
          throw new Error("Passkey verification failed.");

        user = await this.verify({
          authenticator,
          type: "authentication",
          username,
        });
      } else {
        throw new Error("Invalid verification type.");
      }

      // Verify either registration or authentication
      return this.success(user, request, sessionStorage, options);
    } catch (error) {
      if (error instanceof Response) throw error;
      if (error instanceof Error) {
        return await this.failure(
          error.message,
          request,
          sessionStorage,
          options,
          error
        );
      }

      if (typeof error === "string") {
        return await this.failure(
          error,
          request,
          sessionStorage,
          options,
          new Error(error)
        );
      }

      return await this.failure(
        "Unknown error",
        request,
        sessionStorage,
        options,
        new Error(JSON.stringify(error, null, 2))
      );
    }
  }
}
