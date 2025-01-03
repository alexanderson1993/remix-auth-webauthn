import { createCookieSessionStorage } from "react-router";
import { User } from "~/utils/db.server";

type SessionData = {
  user: User;
  challenge?: string;
};

type SessionFlashData = {
  error: string;
};

export const userSession = createCookieSessionStorage<
  SessionData,
  SessionFlashData
>({
  cookie: {
    name: "__session",
    httpOnly: true,
    maxAge: 60 * 60 * 24 * 30,
    path: "/",
    sameSite: "lax",
    secrets: ["s3cret1"],
    secure: process.env.NODE_ENV === "production",
  },
});
