import {
  bufferToBase64URLString,
  startAuthentication,
  startRegistration,
} from "@simplewebauthn/browser";
import type * as React from "react";
import type { WebAuthnOptionsResponse } from "./server.js";

export * from "@simplewebauthn/browser";

export type { WebAuthnOptionsResponse };

export const nanoid = (t = 32) => crypto.getRandomValues(new Uint8Array(t));

export function handleFormSubmit(
  options: WebAuthnOptionsResponse,
  config?: {
    /** Generate an unique user ID when registering new users */
    generateUserId?: () => Uint8Array;

    /**
     * Specify the preference regarding attestation conveyance during credential generation.
     * @link https://www.w3.org/TR/webauthn-2/#enumdef-attestationconveyancepreference
     */
    attestationType?: AttestationConveyancePreference;
  }
) {
  return async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    if (
      !(event.nativeEvent instanceof SubmitEvent) ||
      !(event.nativeEvent.submitter instanceof HTMLButtonElement)
    ) {
      event.preventDefault();
      return false;
    }
    if (event.nativeEvent.submitter.formMethod === "get") {
      return true;
    }
    const formData = new FormData(event.currentTarget);
    const username = formData.get("username")?.toString();

    const target = event.currentTarget;
    const submitButtonValue = event.nativeEvent.submitter.value;
    const type =
      submitButtonValue === "registration"
        ? "registration"
        : submitButtonValue === "authentication"
        ? "authentication"
        : undefined;

    if (!type) {
      throw new Error(
        'When you submit this form, you need to indicate the intent - whether you are registering a new passkey or authenticating an existing passkey. By default, put `name="intent"` attribute on your submit buttons, and set the `value` attribute to either `"registration"` or `"authentication"`.'
      );
    }

    if (type === "registration" && !username) {
      throw new Error(
        "You must provide a username field in your form, and set the `name` attribute to `username`."
      );
    }

    event.preventDefault();

    const responseValue =
      type === "authentication"
        ? JSON.stringify(
            await startAuthentication({
              optionsJSON: {
                challenge: options.challenge,
                allowCredentials: options.authenticators,
                rpId: options.rp.id,
                userVerification: "preferred",
                timeout: 90 * 1000,
              },
            })
          )
        : JSON.stringify(
            await startRegistration({
              optionsJSON: {
                challenge: options.challenge,
                excludeCredentials: options.authenticators,
                rp: options.rp,
                user: {
                  id: bufferToBase64URLString(
                    config?.generateUserId?.() || nanoid()
                  ),
                  name: username!,
                  displayName: username!,
                },
                pubKeyCredParams: [
                  {
                    alg: -7,
                    type: "public-key",
                  },
                  {
                    alg: -257,
                    type: "public-key",
                  },
                ],
                timeout: 90 * 1000,
                attestation: config?.attestationType || "none",
                authenticatorSelection: {
                  residentKey: "discouraged",
                  requireResidentKey: false,
                  userVerification: "preferred",
                },
                extensions: { credProps: true },
              },
            })
          );

    let responseEl = target.querySelector(
      'input[name="response"]'
    ) as HTMLInputElement;
    if (!responseEl) {
      responseEl = Object.assign(document.createElement("input"), {
        type: "hidden",
        name: "response",
      });
      target.prepend(responseEl);
    }
    responseEl.value = responseValue;

    let typeEl = target.querySelector('input[name="type"]') as HTMLInputElement;
    if (!typeEl) {
      typeEl = Object.assign(document.createElement("input"), {
        type: "hidden",
        name: "type",
      });
      target.prepend(typeEl);
    }
    typeEl.value = type;

    target.submit();
  };
}
