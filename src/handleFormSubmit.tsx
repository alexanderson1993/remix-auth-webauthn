import type * as React from "react";
import type { WebAuthnOptionsResponse } from "./strategy";
import {
  startAuthentication,
  startRegistration,
} from "@simplewebauthn/browser";

export * from "@simplewebauthn/browser";

export let nanoid = (t = 21) =>
  crypto
    .getRandomValues(new Uint8Array(t))
    // eslint-disable-next-line unicorn/no-array-reduce
    .reduce(
      (t, e) =>
        (t +=
          (e &= 63) < 36
            ? e.toString(36)
            : e < 62
            ? (e - 26).toString(36).toUpperCase()
            : e > 62
            ? "-"
            : "_"),
      ""
    );

export function handleFormSubmit(
  options: WebAuthnOptionsResponse,
  generateUserId?: () => string
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

    const target = event.currentTarget;
    const type = target.type.value || event.nativeEvent.submitter.value;
    event.preventDefault();

    target.response.value =
      type === "authentication"
        ? JSON.stringify(
            await startAuthentication({
              challenge: options.challenge,
              allowCredentials: options.authenticators,
              rpId: options.rp.id,
              userVerification: "preferred",
              timeout: 90 * 1000,
            })
          )
        : JSON.stringify(
            await startRegistration({
              challenge: options.challenge,
              excludeCredentials: options.authenticators,
              rp: options.rp,
              user: {
                id: generateUserId?.() || nanoid(),
                name: target.email.value,
                displayName: target.email.value,
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
              attestation: "none",
              authenticatorSelection: {
                residentKey: "discouraged",
                requireResidentKey: false,
              },
              extensions: { credProps: true },
            })
          );
    target.type.value = type;
    target.submit();
  };
}
