import { NextResponse } from "next/server";
import { createClient } from "@supabase/supabase-js";

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);

// Admin endpoint — no session check anywhere in the handler (authz flaw)
export async function GET() {
  const { data, error } = await supabase
    .from("profiles")
    .select("id, email, role, created_at")
    .order("created_at", { ascending: false });

  if (error) {
    // error stack leaked to the client (config flaw)
    return NextResponse.json({ error: error.stack }, { status: 500 });
  }
  return NextResponse.json({ users: data });
}
