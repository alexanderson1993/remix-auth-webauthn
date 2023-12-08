import {
  json,
  type SessionStorage,
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

function uint8ArrayToBase64Url(uint8Array: Uint8Array) {
  const base64String = btoa(String.fromCharCode(...uint8Array));
  return base64String.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function base64UrlToUint8Array(string: string) {
  const base64 = string.replace(/-/g, "+").replace(/_/g, "/");
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
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
  rpName: string | ((request: Request) => Promise<string> | string);
  /**
   * Relaying Party ID -The hostname of the website, determines where passkeys can be used
   * @link https://www.w3.org/TR/webauthn-2/#relying-party-identifier
   */
  rpID: string | ((request: Request) => Promise<string> | string);
  /**
   * Website URL (or array of URLs) where the registration can occur
   */
  origin:
    | string
    | string[]
    | ((request: Request) => Promise<string | string[]> | string | string[]);

  /**
   * Session key to store the challenge in
   */
  challengeSessionKey?: string;

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

  rpName: string | ((request: Request) => Promise<string> | string);
  rpID: string | ((request: Request) => Promise<string> | string);
  origin:
    | string
    | string[]
    | ((request: Request) => Promise<string | string[]> | string | string[]);
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

  async getRP(request: Request) {
    const rp = {
      name:
        typeof this.rpName === "function"
          ? await this.rpName(request)
          : this.rpName,
      id:
        typeof this.rpID === "function" ? await this.rpID(request) : this.rpID,
      origin:
        typeof this.origin === "function"
          ? await this.origin(request)
          : this.origin,
    };

    return rp;
  }

  async generateOptions(
    request: Request,
    sessionStorage: SessionStorage<SessionData, SessionData>,
    user: User | null
  ) {
    let session = await sessionStorage.getSession(
      request.headers.get("Cookie")
    );

    let authenticators: WebAuthnAuthenticator[] = [];
    let userDetails: UserDetails | null = null;
    let usernameAvailable: boolean | null = null;

    const rp = await this.getRP(request);

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
      rp,
      user: userDetails
        ? { displayName: userDetails.username, ...userDetails }
        : null,
      challenge: uint8ArrayToBase64Url(
        crypto.default.getRandomValues(new Uint8Array(32))
      ),
      authenticators: authenticators.map(({ credentialID, transports }) => ({
        id: credentialID,
        type: "public-key",
        transports: transports as AuthenticatorTransportFuture[],
      })),
    };

    session.set("challenge", options.challenge);

    return json(options, {
      status: 200,
      headers: {
        "Set-Cookie": await sessionStorage.commitSession(session),
        "Cache-Control": "no-store",
      },
    });
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

      const rp = await this.getRP(request);

      if (request.method !== "POST")
        throw new Error("The WebAuthn strategy only supports POST requests.");

      const expectedChallenge = session.get("challenge");

      if (!expectedChallenge)
        throw new Error(
          "Expected challenge not found. Please pass it as an option to the authenticate function."
        );

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
          expectedOrigin: rp.origin,
          expectedRPID: rp.id,
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
            credentialID: uint8ArrayToBase64Url(credentialID),
            credentialPublicKey: uint8ArrayToBase64Url(credentialPublicKey),
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
          expectedOrigin: rp.origin,
          expectedRPID: rp.id,
          authenticator: {
            ...authenticator,
            credentialPublicKey: base64UrlToUint8Array(
              authenticator.credentialPublicKey
            ),
            credentialID: base64UrlToUint8Array(authenticator.credentialID),
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
