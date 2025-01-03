import { userSession } from "~/utils/session.server";
import { Route } from "./+types/logout";
import { redirect } from "react-router";

export async function loader({ request }: Route.ActionArgs) {
  let session = await userSession.getSession(request.headers.get("cookie"));
  throw redirect("/", {
    headers: { "Set-Cookie": await userSession.destroySession(session) },
  });
}
export async function action({ request }: Route.ActionArgs) {
  let session = await userSession.getSession(request.headers.get("cookie"));
  throw redirect("/", {
    headers: { "Set-Cookie": await userSession.destroySession(session) },
  });
}
