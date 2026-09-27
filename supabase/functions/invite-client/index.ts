// Deploy path: supabase/functions/invite-client/index.ts
//
// SUPABASE_URL, SUPABASE_ANON_KEY, and SUPABASE_SERVICE_ROLE_KEY are
// automatically available as env vars inside every Edge Function —
// you do not need to set these yourself.

import { createClient } from "npm:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;

Deno.serve(async (req) => {
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "authorization, content-type",
  };
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) throw new Error("Missing Authorization header");

    // Verify the CALLER is a logged-in trainer, using their own token
    // (not the service key) — this is the security check.
    const callerClient = createClient(SUPABASE_URL, ANON_KEY, {
      global: { headers: { Authorization: authHeader } },
    });
    const { data: { user }, error: userErr } = await callerClient.auth.getUser();
    if (userErr || !user) throw new Error("Invalid session");

    const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);
    const { data: callerProfile } = await admin
      .from("profiles").select("role").eq("id", user.id).single();
    if (callerProfile?.role !== "trainer") throw new Error("Only trainers can invite clients");

    const { name, email, phone } = await req.json();
    if (!name || !email) throw new Error("name and email are required");

    // Record the invite (RLS-safe: acting as the trainer via admin client, but
    // scoped manually since we're using the service key here)
    const { data: invite, error: invErr } = await admin
      .from("client_invites")
      .insert({ trainer_id: user.id, name, email, phone })
      .select().single();
    if (invErr) throw invErr;

    // Send the actual invite email via Supabase Auth
    const { error: sendErr } = await admin.auth.admin.inviteUserByEmail(email, {
      data: { name, role: "client" },
    });
    if (sendErr) throw sendErr;

    return new Response(JSON.stringify({ ok: true, invite }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: e.message }), {
      status: 400,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
