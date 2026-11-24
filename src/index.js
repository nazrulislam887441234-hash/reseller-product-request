const ALLOWED_ORIGINS = [
  "https://reseller.ghotimarket.com",
  "http://localhost:5500",
  "http://127.0.0.1:5500"
];

const MAX_BODY_BYTES = 10240; // 10 KB limit

function getCorsHeaders(origin) {
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin)
    ? origin
    : "https://reseller.ghotimarket.com";

  return {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Request-Secret",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}

function jsonResponse(data, status, corsHeaders) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json; charset=utf-8"
    }
  });
}

async function verifyFirebaseUser(idToken, expectedUid, firebaseApiKey) {
  if (!idToken || !firebaseApiKey) return false;

  const verifyUrl = `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(firebaseApiKey)}`;
  const res = await fetch(verifyUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ idToken })
  });

  if (!res.ok) return false;

  const result = await res.json();
  const user = result?.users?.[0];
  return Boolean(user && user.localId === expectedUid);
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const corsHeaders = getCorsHeaders(origin);

    // Handle CORS Preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    // Reject methods other than POST
    if (request.method !== "POST") {
      return jsonResponse(
        { success: false, error: "Method Not Allowed. Only POST is supported." },
        405,
        corsHeaders
      );
    }

    // Check Content-Length to reject oversized payloads
    const contentLength = Number(request.headers.get("Content-Length") || "0");
    if (contentLength > MAX_BODY_BYTES) {
      return jsonResponse(
        { success: false, error: "Payload Too Large." },
        413,
        corsHeaders
      );
    }

    // Read raw body safely with size limit
    let rawBody;
    try {
      rawBody = await request.text();
      if (new TextEncoder().encode(rawBody).length > MAX_BODY_BYTES) {
        return jsonResponse(
          { success: false, error: "Payload Too Large." },
          413,
          corsHeaders
        );
      }
    } catch {
      return jsonResponse(
        { success: false, error: "Invalid request stream." },
        400,
        corsHeaders
      );
    }

    let payload;
    try {
      payload = JSON.parse(rawBody);
    } catch {
      return jsonResponse(
        { success: false, error: "Invalid JSON body." },
        400,
        corsHeaders
      );
    }

    // Validate Required Fields
    const productName = typeof payload.productName === "string" ? payload.productName.trim() : "";
    const note = typeof payload.note === "string" ? payload.note.trim() : "";
    const important = typeof payload.important === "string" ? payload.important.trim() : "";
    const uid = typeof payload.uid === "string" ? payload.uid.trim() : "";
    const requestId = typeof payload.requestId === "string" ? payload.requestId.trim() : "";

    if (!productName || !important || !uid || !requestId) {
      return jsonResponse(
        { success: false, error: "Missing required fields." },
        400,
        corsHeaders
      );
    }

    if (productName.length > 250 || important.length > 1500 || note.length > 1500) {
      return jsonResponse(
        { success: false, error: "One or more fields exceed maximum allowed length." },
        400,
        corsHeaders
      );
    }

    // Verify Request Authorization (Firebase ID Token OR Server-to-Server Shared Secret)
    const authHeader = request.headers.get("Authorization") || "";
    const sharedSecretHeader = request.headers.get("X-Request-Secret") || "";

    let isAuthorized = false;

    if (env.REQUEST_SECRET && sharedSecretHeader && sharedSecretHeader === env.REQUEST_SECRET) {
      isAuthorized = true;
    } else if (authHeader.startsWith("Bearer ")) {
      const idToken = authHeader.slice(7).trim();
      isAuthorized = await verifyFirebaseUser(idToken, uid, env.FIREBASE_WEB_API_KEY);
    }

    if (!isAuthorized) {
      return jsonResponse(
        { success: false, error: "Unauthorized request." },
        401,
        corsHeaders
      );
    }

    // Ensure Telegram Secrets Exist
    if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) {
      return jsonResponse(
        { success: false, error: "Server notification configuration incomplete." },
        500,
        corsHeaders
      );
    }

    // Format Telegram Message
    const formattedNote = note || "N/A";
    const telegramMessage = [
      "NEW PRODUCT REQUEST",
      `Product Name: ${productName}`,
      `Note: ${formattedNote}`,
      `Important: ${important}`,
      `Reseller UID: ${uid}`,
      `Request ID: ${requestId}`,
      "Platform: Reseller Ghoti Market"
    ].join("\n");

    try {
      const telegramUrl = `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`;
      const tgResponse = await fetch(telegramUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          chat_id: env.TELEGRAM_CHAT_ID,
          text: telegramMessage,
          disable_web_page_preview: true
        })
      });

      const tgResult = await tgResponse.json();

      if (!tgResponse.ok || !tgResult.ok) {
        return jsonResponse(
          {
            success: false,
            error: "Failed to deliver Telegram notification.",
            details: tgResult.description || "Telegram API error"
          },
          502,
          corsHeaders
        );
      }

      return jsonResponse(
        { success: true, message: "Notification sent successfully." },
        200,
        corsHeaders
      );
    } catch {
      return jsonResponse(
        { success: false, error: "Internal error while contacting Telegram API." },
        502,
        corsHeaders
      );
    }
  }
};
