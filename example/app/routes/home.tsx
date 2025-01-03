import { authenticator, webAuthnStrategy } from "~/utils/auth.server";
import type { Route } from "./+types/home";
import { userSession } from "~/utils/session.server";
import { data, Form, redirect } from "react-router";
import { handleFormSubmit } from "remix-auth-webauthn/browser";

export function meta({}: Route.MetaArgs) {
  return [{ title: "Remix Auth Webauthn Demo" }];
}

export async function loader({ request }: Route.LoaderArgs) {
  const session = await userSession.getSession(request.headers.get("cookie"));
  const user = session.get("user");
  const options = await webAuthnStrategy.generateOptions(request, user);

  // Set the challenge in a session cookie so it can be accessed later.
  session.set("challenge", options.challenge);

  // Update the cookie
  return data(
    { options, user },
    {
      headers: {
        "Set-Cookie": await userSession.commitSession(session),
        "Cache-Control": "no-store",
      },
    }
  );
}

export async function action({ request }: Route.ActionArgs) {
  const session = await userSession.getSession(request.headers.get("cookie"));

  try {
    const user = await authenticator.authenticate("webauthn", request);
    session.set("user", user);

    throw redirect("/", {
      headers: {
        "Set-Cookie": await userSession.commitSession(session),
      },
    });
  } catch (error) {
    // This allows us to return errors to the page without triggering the error boundary.
    if (error instanceof Error) {
      return { error, user: null };
    }
    // Throw other errors, such as responses that need to redirect the browser.
    throw error;
  }
}

export default function Home({ loaderData, actionData }: Route.ComponentProps) {
  return loaderData.user ? (
    <div className="flex flex-col gap-2 m-8 w-64">
      <p>
        Logged in as {loaderData.user.username} ({loaderData.user.id})
      </p>
      <Form method="POST" action="/logout">
        <button className="px-2 py-1 bg-blue-500 rounded">Logout</button>
      </Form>
    </div>
  ) : (
    <Form
      onSubmit={handleFormSubmit(loaderData.options)}
      method="POST"
      className="flex flex-col gap-2 m-8 w-64"
    >
      <label>Username</label>
      <input
        type="text"
        name="username"
        placeholder="alexanderson1993"
        className="p-2 rounded"
      />
      <button formMethod="GET" className="px-2 py-1 bg-blue-500 rounded">
        Check Username
      </button>
      <button
        name="intent"
        value="registration"
        disabled={loaderData.options.usernameAvailable !== true}
        className="px-2 py-1 bg-orange-500 rounded disabled:opacity-50"
      >
        Register
      </button>
      <button
        name="intent"
        value="authentication"
        className="px-2 py-1 bg-green-500 rounded"
      >
        Authenticate
      </button>
      {actionData?.error ? <div>{actionData.error.message}</div> : null}
    </Form>
  );
}
