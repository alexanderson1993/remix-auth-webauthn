import {
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { isoBase64URL } from "@simplewebauthn/server/helpers";
import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  PublicKeyCredentialDescriptorJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/types";
import { Strategy } from "remix-auth/strategy";
import { SessionStorage } from "react-router";
interface WebAuthnAuthenticator {
  id: string;
  transports: string[];
}

export interface Authenticator {
  id: string;
  userId: string;
  publicKey: string;
  counter: number;
  credentialDeviceType: string;
  credentialBackedUp: boolean;
  transports: string;
  aaguid: string;
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
   * The React Router session storage which stores the challenge value
   */
  sessionStorage: any;
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
   * Session key to store the challenge in. Defaults to "challenge"
   */
  challengeSessionKey?: string;

  /**
   * Return a list of authenticators associated with the user.
   * @param user object
   * @returns Authenticator
   */
  getUserAuthenticators: (
    user: User | null | undefined
  ) => Promise<WebAuthnAuthenticator[]>;
  /**
   * Transform the user object into the shape expected by the strategy.
   * You can use a regular username, the users email address, or something else.
   * @param user object
   * @returns UserDetails
   */
  getUserDetails: (
    user: User | null | undefined
  ) => Promise<UserDetails | null>;

  /**
   * Find a user in the database with their username/email.
   * @param username
   * @returns User object
   */
  getUserByUsername: (username: string) => Promise<User | null>;
  /**
   * Find an authenticator in the database by its credential ID
   * @param id
   * @returns Authenticator
   */
  getAuthenticatorById: (id: string) => Promise<Authenticator | null>;
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
  sessionStorage: SessionStorage;
  challengeSessionKey: string = "challenge";

  rpName: string | ((request: Request) => Promise<string> | string);
  rpID: string | ((request: Request) => Promise<string> | string);
  origin:
    | string
    | string[]
    | ((request: Request) => Promise<string | string[]> | string | string[]);
  getUserAuthenticators: (
    user: User | null | undefined
  ) => Promise<WebAuthnAuthenticator[]>;
  getUserDetails: (
    user: User | null | undefined
  ) => Promise<UserDetails | null>;
  getUserByUsername: (username: string) => Promise<User | null>;
  getAuthenticatorById: (id: string) => Promise<Authenticator | null>;

  constructor(
    options: WebAuthnOptions<User>,
    verify: Strategy.VerifyFunction<User, WebAuthnVerifyParams>
  ) {
    super(verify);
    this.sessionStorage = options.sessionStorage;
    this.rpName = options.rpName;
    this.rpID = options.rpID;
    this.origin = options.origin;
    this.getUserAuthenticators = options.getUserAuthenticators;
    this.getUserDetails = options.getUserDetails;
    this.getUserByUsername = options.getUserByUsername;
    this.getAuthenticatorById = options.getAuthenticatorById;
    this.challengeSessionKey = options.challengeSessionKey || "challenge";
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

  async generateOptions(request: Request, user: User | null | undefined) {
    let authenticators: WebAuthnAuthenticator[] = [];
    let userDetails: UserDetails | null = null;
    let usernameAvailable: boolean | null = null;

    const rp = await this.getRP(request);

    const username = new URL(request.url).searchParams.get("username");
    if (!user) {
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

    const options: WebAuthnOptionsResponse = {
      usernameAvailable,
      rp,
      user: userDetails
        ? { displayName: userDetails.username, ...userDetails }
        : null,
      challenge: isoBase64URL.fromBuffer(
        crypto.getRandomValues(new Uint8Array(32))
      ),
      authenticators: authenticators.map(({ id, transports }) => ({
        id,
        type: "public-key",
        transports: transports as AuthenticatorTransportFuture[],
      })),
    };

    return options;
  }
  async authenticate(request: Request): Promise<User> {
    const session = await this.sessionStorage.getSession(
      request.headers.get("Cookie")
    );

    const rp = await this.getRP(request);

    if (request.method !== "POST")
      throw new Error("The WebAuthn strategy only supports POST requests.");

    const expectedChallenge = session.get(this.challengeSessionKey);

    if (!expectedChallenge) {
      throw new Error(
        `Expected challenge not found. It needs to set to the \`${this.challengeSessionKey}\` property on the auth session storage.`
      );
    }

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
        requireUserVerification: false,
      });

      if (verification.verified && verification.registrationInfo) {
        const {
          credential: { id, publicKey, counter, transports },
          credentialBackedUp,
          credentialDeviceType,
          aaguid,
        } = verification.registrationInfo;

        const newAuthenticator = {
          id,
          publicKey: isoBase64URL.fromBuffer(publicKey),
          counter,
          credentialBackedUp,
          credentialDeviceType,
          transports: transports?.join(",") || "",
          aaguid,
        };
        return this.verify({
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
        credential: {
          ...authenticator,
          publicKey: isoBase64URL.toBuffer(authenticator.publicKey),
          transports: authenticator.transports.split(
            ","
          ) as AuthenticatorTransportFuture[],
        },
        requireUserVerification: false,
      });

      if (!verification.verified)
        throw new Error("Passkey verification failed.");

      return this.verify({
        authenticator,
        type: "authentication",
        username,
      });
    }
    throw new Error("Invalid verification type.");
  }
}
