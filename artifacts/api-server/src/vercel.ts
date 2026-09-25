import type { IncomingMessage, ServerResponse } from "node:http";
import app from "./app";

// Vercel routes /api/* to this single function as /api?__path=*; restore the original path for Express.
export default function handler(req: IncomingMessage, res: ServerResponse) {
  const url = new URL(req.url ?? "/", "http://localhost");
  const path = url.searchParams.get("__path");
  if (path !== null) {
    url.searchParams.delete("__path");
    req.url = `/api/${path}${url.search}`;
  }
  app(req, res);
}
