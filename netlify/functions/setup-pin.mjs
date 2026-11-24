
import {
  randomBytes,
  scryptSync,
  timingSafeEqual
} from "node:crypto";

export default async (req) => {
  if (req.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  try {
    const { playerId, pin, setupSecret } = await req.json();

    const expectedSecret = process.env.PIN_SETUP_SECRET;

    if (!expectedSecret || typeof setupSecret !== "string") {
      return Response.json(
        { error: "Not authorised." },
        { status: 401 }
      );
    }

    const supplied = Buffer.from(setupSecret);
    const expected = Buffer.from(expectedSecret);

    if (
      supplied.length !== expected.length ||
      !timingSafeEqual(supplied, expected)
    ) {
      return Response.json(
        { error: "Not authorised." },
        { status: 401 }
      );
    }

    if (
      !["bharanyu", "abrar", "mahad", "usman"].includes(playerId) ||
      typeof pin !== "string" ||
      !/^\d{8,12}$/.test(pin)
    ) {
      return Response.json(
        { error: "Invalid player or PIN." },
        { status: 400 }
      );
    }

    const salt = randomBytes(16).toString("hex");
    const hash = scryptSync(pin, salt, 64).toString("hex");
    const pinHash = `scrypt$${salt}$${hash}`;

    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

    if (!url || !key) {
      throw new Error("Missing Supabase environment variables.");
    }

    const response = await fetch(
      `${url.replace(/\/+$/, "")}/rest/v1/players?id=eq.${encodeURIComponent(playerId)}`,
      {
        method: "PATCH",
        headers: {
          apikey: key,
          Authorization: `Bearer ${key}`,
          "Content-Type": "application/json",
          Prefer: "return=representation"
        },
        body: JSON.stringify({ pin_hash: pinHash })
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      console.error(
        "Supabase update failed:",
        response.status,
        errorText
      );
      throw new Error("Database update failed.");
    }

    const updatedRows = await response.json();

    if (updatedRows.length !== 1) {
      throw new Error("Player record was not updated.");
    }

    return Response.json({ success: true });

  } catch (error) {
    console.error("PIN setup error:", error.message);

    return Response.json(
      { error: "PIN setup failed." },
      { status: 500 }
    );
  }
};
