
import { createHmac, scryptSync, timingSafeEqual } from "node:crypto";

export default async (req) => {
  if (req.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  try {
    const { playerId, pin } = await req.json();

    if (
      typeof playerId !== "string" ||
      typeof pin !== "string" ||
      !/^\d{8,12}$/.test(pin)
    ) {
      return Response.json(
        { error: "Invalid player ID or PIN." },
        { status: 400 }
      );
    }

    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
    const secret = process.env.SESSION_SECRET;

    if (!url || !key || !secret) {
      throw new Error("Server environment variables are missing.");
    }

    const response = await fetch(
      `${url}/rest/v1/players?id=eq.${encodeURIComponent(playerId)}&select=id,name,pin_hash`,
      {
        headers: {
          apikey: key,
          Authorization: `Bearer ${key}`
        }
      }
    );

    if (!response.ok) throw new Error("Database request failed.");

    const players = await response.json();
    const player = players[0];

    if (!player?.pin_hash) {
      return Response.json(
        { error: "Login details are not set up yet." },
        { status: 401 }
      );
    }

    const [algorithm, salt, storedHash] = player.pin_hash.split("$");

    if (algorithm !== "scrypt" || !salt || !storedHash) {
      throw new Error("Invalid stored PIN format.");
    }

    const submittedHash = scryptSync(pin, salt, 64);
    const expectedHash = Buffer.from(storedHash, "hex");

    if (
      expectedHash.length !== submittedHash.length ||
      !timingSafeEqual(submittedHash, expectedHash)
    ) {
      return Response.json(
        { error: "Incorrect player or PIN." },
        { status: 401 }
      );
    }

    const expires = Date.now() + 7 * 24 * 60 * 60 * 1000;
    const payload = Buffer.from(
      JSON.stringify({ playerId: player.id, expires })
    ).toString("base64url");

    const signature = createHmac("sha256", secret)
      .update(payload)
      .digest("base64url");

    return Response.json(
      { success: true, player: { id: player.id, name: player.name } },
      {
        headers: {
          "Set-Cookie": `squad_session=${payload}.${signature}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
        }
      }
    );
  } catch (error) {
    console.error("Login error:", error.message);
    return Response.json(
      { error: "Something went wrong. Please try again." },
      { status: 500 }
    );
  }
};
