export async function onRequestPost({ request, env }) {
    // Only accept JSON
    const contentType = request.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) {
      return json({ error: "Expected JSON" }, 415);
    }
  
    const body = await request.json().catch(() => null);
    if (!body) return json({ error: "Invalid JSON" }, 400);
  
    const name = (body.name || "").toString().trim();
    const email = (body.email || "").toString().trim();
    const message = (body.message || "").toString().trim();
    const company = (body.company || "").toString().trim(); // honeypot
  
    // Honeypot: if filled, silently accept (bot)
    if (company) return json({ ok: true }, 200);
  
    // Basic validation
    if (!email || !message) return json({ error: "Missing required fields" }, 400);
    if (message.length > 5000) return json({ error: "Message too long" }, 400);
  
    // --- Turnstile verification ---
    const token = body["cf-turnstile-response"];
    if (!token) return json({ error: "Missing captcha token" }, 400);
  
    const verify = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          secret: env.TURNSTILE_SECRET_KEY,
          response: token,
          remoteip: request.headers.get("CF-Connecting-IP"),
        }),
      }
    );
  
    const outcome = await verify.json().catch(() => null);
    if (!outcome?.success) return json({ error: "Captcha failed" }, 403);
  
    // --- Send email via Resend ---
    const resp = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: env.CONTACT_FROM,   // e.g. "Resonant Artisan <contact@resonantartisan.com>"
        to: [env.CONTACT_TO],     // e.g. "artisanresonant@gmail.com"
        reply_to: email,
        subject: `New message from ${name || "someone"} (${email})`,
        text: `Name: ${name}\nEmail: ${email}\n\n${message}`,
      }),
    });
  
    if (!resp.ok) {
      const errText = await resp.text().catch(() => "");
      return json({ error: "Resend failed", detail: errText.slice(0, 400) }, 502);
    }
  
    return json({ ok: true }, 200);
  }
  
  function json(obj, status = 200) {
    return new Response(JSON.stringify(obj), {
      status,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
      },
    });
  }
  