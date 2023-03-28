import * as React from "react";
import { FormProps, useLoaderData } from "@remix-run/react";
import { Form } from "@remix-run/react";
import {
  startAuthentication,
  startRegistration,
} from "@simplewebauthn/browser";
import type { WebAuthnOptionsResponse } from "./strategy";
import { nanoid } from "nanoid";

export interface WebAuthnFormProps
  extends FormProps,
    React.RefAttributes<HTMLFormElement> {
  generateUserId?: () => string;
}

export function WebAuthnForm({
  onSubmit,
  children,
  generateUserId,
  ...props
}: WebAuthnFormProps) {
  const options = useLoaderData<WebAuthnOptionsResponse>();

  return (
    <Form
      {...props}
      method="post"
      onSubmit={async (event) => {
        // If the user-provided submit function throws,
        // return true and submit the form like normal.
        try {
          onSubmit?.(event);
        } catch {
          return true;
        }
        if (!(document.activeElement instanceof HTMLButtonElement)) {
          event.preventDefault();
          return false;
        }

        const target = event.currentTarget;
        const type = document.activeElement.value;
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
      }}
    >
      <input type="hidden" name="response" />
      <input type="hidden" name="type" />
      {children}
    </Form>
  );
}
