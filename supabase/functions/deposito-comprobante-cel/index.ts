// Edge Function de la web del celular del Depósito (sube comprobantes de un ingreso).
// Desde oct-2026 vive en el Supabase compartido (zpwccecovhjmeibxafkg): tablas en
// el schema `deposito` y archivos en el bucket `deposito-comprobantes`. Antes era
// `comprobante-cel` en el proyecto DEPOSITO-AVALOS (ioycuhefaalpqivhhryb, dado de baja).
//
// Seguridad (auditoría oct-2026):
//  - Bloqueo por intentos de PIN ATÓMICO: el intento se reserva en la base
//    (deposito.pin_reservar_intento, un único INSERT ... ON CONFLICT) ANTES de
//    comparar, así N pedidos en paralelo no pueden probar más de 5 PINs cada
//    15 minutos. Si el PIN es correcto se devuelve el intento (pin_intento_ok).
//    Ver supabase/migrations/20261025120000_deposito_pin_intentos.sql.
//  - Comparación del PIN en tiempo constante.
//  - Archivo: máximo 15 MB y solo JPEG/PNG/WEBP/HEIC/PDF (se verifica también
//    la firma del contenido, no solo el MIME declarado).
//  - Errores: mensaje genérico al cliente, detalle solo en console.error.
import { createClient } from "jsr:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const BUCKET = "deposito-comprobantes";
const FUNCION = "deposito-comprobante-cel";
const MAX_BYTES = 15 * 1024 * 1024; // 15 MB del archivo decodificado
const MAX_B64 = Math.ceil(MAX_BYTES / 3) * 4 + 4;
const MAX_BODY = MAX_B64 + 64 * 1024; // base64 + resto del JSON
const MIMES = new Set(["image/jpeg", "image/png", "image/webp", "image/heic", "application/pdf"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function json(obj: unknown, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });
}

function slug(n: string) {
  return (n || "archivo").replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 80);
}

// IP real del cliente (delante está Cloudflare: cf-connecting-ip). Igual que
// en las otras funciones con PIN.
function ipDe(req: Request): string {
  const cf = (req.headers.get("cf-connecting-ip") || "").trim();
  if (cf) return cf;
  const xf = (req.headers.get("x-forwarded-for") || "").split(",").map((s) => s.trim()).filter(Boolean);
  return xf[0] || "desconocida";
}

// Comparación en tiempo constante (no corta en el primer carácter distinto).
function pinIgual(a: string, b: string): boolean {
  const ea = new TextEncoder().encode(a), eb = new TextEncoder().encode(b);
  let d = ea.length ^ eb.length;
  for (let i = 0; i < Math.max(ea.length, eb.length); i++) d |= (ea[i] ?? 0) ^ (eb[i] ?? 0);
  return d === 0;
}

// Firma (magic bytes) del contenido según el MIME declarado.
function firmaOk(mime: string, b: Uint8Array): boolean {
  const asc = (i: number, n: number) => String.fromCharCode(...b.subarray(i, i + n));
  switch (mime) {
    case "image/jpeg": return b.length > 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff;
    case "image/png": return b.length > 8 && b[0] === 0x89 && asc(1, 3) === "PNG";
    case "image/webp": return b.length > 12 && asc(0, 4) === "RIFF" && asc(8, 4) === "WEBP";
    case "image/heic": return b.length > 12 && asc(4, 4) === "ftyp";
    case "application/pdf": return b.length > 5 && asc(0, 5) === "%PDF-";
    default: return false;
  }
}

function decodificar(b64: string): Uint8Array | null {
  try {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

function respBloqueo(seg: number): Response {
  const min = Math.max(1, Math.ceil(seg / 60));
  return json({ error: `Demasiados intentos, probá de nuevo en ${min} minuto${min === 1 ? "" : "s"}`, bloqueado: true, espera: seg }, 429);
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "Método no permitido" }, 405);
  try {
    const largo = Number(req.headers.get("content-length") || 0);
    if (largo > MAX_BODY) return json({ error: "El archivo supera los 15 MB" }, 413);

    const svc = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
      { db: { schema: "deposito" } },
    );
    let body: any;
    try { body = await req.json(); } catch { return json({ error: "Pedido inválido" }, 400); }
    const { accion, ingreso } = body ?? {};
    const pin = typeof body?.pin === "string" ? body.pin : String(body?.pin ?? "");
    if (!pin) return json({ error: "PIN incorrecto" }, 401);

    // 1) Reservar el intento ANTES de comparar (atómico en la base).
    const ip = ipDe(req);
    const { data: intento, error: eInt } = await svc.rpc("pin_reservar_intento", { p_ip: ip, p_funcion: FUNCION });
    if (eInt || !intento) {
      console.error("pin_reservar_intento", eInt);
      return json({ error: "No se pudo procesar el pedido" }, 500);
    }
    if (!intento.permitido) return respBloqueo(Number(intento.espera) || 900);

    // 2) Comparar en tiempo constante.
    const { data: p, error: eP } = await svc.from("parametros").select("valor").eq("clave", "pin_celular").single();
    if (eP) console.error("parametros", eP);
    const esperado = p?.valor == null ? "" : String(p.valor);
    if (esperado === "" || !pinIgual(pin, esperado)) return json({ error: "PIN incorrecto" }, 401);

    // 3) PIN correcto: devolver el intento reservado.
    const { error: eOk } = await svc.rpc("pin_intento_ok", { p_ip: ip, p_funcion: FUNCION });
    if (eOk) console.error("pin_intento_ok", eOk);

    if (!ingreso) return json({ error: "Falta el ingreso" }, 400);
    if (typeof ingreso !== "string" || !UUID.test(ingreso)) return json({ error: "Ingreso no encontrado" }, 404);

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
      const { tipo, data_base64 } = body;
      const nombre = String(body.nombre ?? "archivo").slice(0, 200);
      const mime = String(body.mime ?? "").toLowerCase().split(";")[0].trim();
      if (!data_base64 || typeof data_base64 !== "string") return json({ error: "Falta el archivo" }, 400);
      if (!MIMES.has(mime)) return json({ error: "Tipo de archivo no permitido (solo JPG, PNG, WEBP, HEIC o PDF)" }, 415);
      if (data_base64.length > MAX_B64) return json({ error: "El archivo supera los 15 MB" }, 413);
      const bytes = decodificar(data_base64);
      if (!bytes || bytes.length === 0) return json({ error: "Archivo inválido" }, 400);
      if (bytes.length > MAX_BYTES) return json({ error: "El archivo supera los 15 MB" }, 413);
      if (!firmaOk(mime, bytes)) return json({ error: "El contenido no coincide con el tipo de archivo" }, 415);

      const path = `${ingreso}/${crypto.randomUUID()}_${slug(nombre)}`;
      const up = await svc.storage.from(BUCKET).upload(path, bytes, { contentType: mime });
      if (up.error) {
        console.error("storage.upload", up.error);
        return json({ error: "No se pudo guardar el archivo" }, 500);
      }
      const t = ["factura", "remito", "otro"].includes(tipo) ? tipo : "otro";
      const { error: eIns } = await svc.from("comprobantes").insert({
        ingreso_id: ingreso, proveedor_id: ing.proveedor_id, tipo: t,
        nombre, path, mime, tamano: bytes.length, origen: "celular",
      });
      if (eIns) {
        console.error("comprobantes.insert", eIns);
        await svc.storage.from(BUCKET).remove([path]); // no dejar el archivo huérfano
        return json({ error: "No se pudo registrar el comprobante" }, 500);
      }
      return json({ ok: true });
    }

    return json({ error: "acción inválida" }, 400);
  } catch (e) {
    console.error("deposito-comprobante-cel", e);
    return json({ error: "Error interno, probá de nuevo" }, 500);
  }
});
