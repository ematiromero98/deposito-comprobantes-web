// Edge Function de la web del celular del Depósito (sube comprobantes de un ingreso).
// Desde oct-2026 vive en el Supabase compartido (zpwccecovhjmeibxafkg): tablas en
// el schema `deposito` y archivos en el bucket `deposito-comprobantes`. Antes era
// `comprobante-cel` en el proyecto DEPOSITO-AVALOS (ioycuhefaalpqivhhryb, dado de baja).
import { createClient } from "jsr:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const BUCKET = "deposito-comprobantes";

function json(obj: unknown, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });
}

function slug(n: string) {
  return (n || "archivo").replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 80);
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const svc = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
      { db: { schema: "deposito" } },
    );
    const body = await req.json();
    const { accion, pin, ingreso } = body ?? {};

    const { data: p } = await svc.from("parametros").select("valor").eq("clave", "pin_celular").single();
    if (!p || String(pin) !== String(p.valor)) return json({ error: "PIN incorrecto" }, 401);
    if (!ingreso) return json({ error: "Falta el ingreso" }, 400);

    const { data: ing } = await svc
      .from("ingresos")
      .select("numero, fecha, proveedor_id, proveedores(nombre)")
      .eq("id", ingreso)
      .single();
    if (!ing) return json({ error: "Ingreso no encontrado" }, 404);
    const provNombre = (ing as any).proveedores?.nombre ?? null;

    if (accion === "info") {
      const { count } = await svc
        .from("comprobantes").select("id", { count: "exact", head: true })
        .eq("ingreso_id", ingreso);
      return json({ numero: ing.numero, fecha: ing.fecha, proveedor: provNombre, adjuntos: count ?? 0 });
    }

    if (accion === "subir") {
      const { tipo, nombre, mime, data_base64 } = body;
      if (!data_base64) return json({ error: "Falta el archivo" }, 400);
      const bin = atob(data_base64);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      const path = `${ingreso}/${crypto.randomUUID()}_${slug(nombre)}`;
      const up = await svc.storage.from(BUCKET).upload(path, bytes, {
        contentType: mime || "application/octet-stream",
      });
      if (up.error) return json({ error: up.error.message }, 500);
      const t = ["factura", "remito", "otro"].includes(tipo) ? tipo : "otro";
      await svc.from("comprobantes").insert({
        ingreso_id: ingreso, proveedor_id: ing.proveedor_id, tipo: t,
        nombre, path, mime, tamano: bytes.length, origen: "celular",
      });
      return json({ ok: true });
    }

    return json({ error: "acción inválida" }, 400);
  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});
