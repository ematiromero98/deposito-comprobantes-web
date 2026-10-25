-- Bloqueo ATÓMICO por intentos de PIN para la Edge Function
-- deposito-comprobante-cel (proyecto compartido zpwccecovhjmeibxafkg, schema deposito).
--
-- Diseño: una fila por (IP, función). El intento se RESERVA (se cuenta) ANTES de
-- comparar el PIN, con un único INSERT ... ON CONFLICT DO UPDATE ... RETURNING.
-- Postgres bloquea la fila mientras dura esa sentencia, así que N pedidos en
-- paralelo se serializan: solo los primeros 5 de la ventana obtienen
-- permitido = true y el resto se rechaza sin llegar a comparar el PIN.
-- Si el PIN resulta correcto, la función llama a pin_intento_ok, que devuelve
-- (descuenta) el intento reservado.
--
-- Reglas: 5 intentos en 15 minutos. Al 5º intento se marca bloqueado_hasta
-- (15 minutos); a partir del 6º se rechaza sin comparar. Si el 5º era correcto,
-- pin_intento_ok saca el bloqueo.
--
-- Solo la usa la Edge Function con service_role: tabla con RLS y sin políticas,
-- funciones SECURITY DEFINER con search_path vacío y EXECUTE solo para service_role.

create table if not exists deposito.pin_intentos (
  ip              text        not null,
  funcion         text        not null,
  fallidos        integer     not null default 0,
  primer_fallo    timestamptz not null default now(),
  bloqueado_hasta timestamptz,
  actualizado     timestamptz not null default now(),
  primary key (ip, funcion)
);
alter table deposito.pin_intentos enable row level security;
revoke all on table deposito.pin_intentos from public, anon, authenticated;
comment on table deposito.pin_intentos is
  'deposito-comprobante-cel: intentos de PIN por IP (5 en 15 min => bloqueo 15 min). Se escribe solo con deposito.pin_reservar_intento / deposito.pin_intento_ok.';

-- Reserva un intento. Devuelve {"permitido": bool, "espera": segundos}.
create or replace function deposito.pin_reservar_intento(p_ip text, p_funcion text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  c_max     constant integer  := 5;
  c_ventana constant interval := interval '15 minutes';
  c_bloqueo constant interval := interval '15 minutes';
  v_fallidos integer;
  v_hasta    timestamptz;
begin
  if p_ip is null or p_funcion is null then
    raise exception 'pin_reservar_intento: ip y funcion son obligatorios';
  end if;

  insert into deposito.pin_intentos as t (ip, funcion, fallidos, primer_fallo, bloqueado_hasta, actualizado)
  values (left(p_ip, 100), left(p_funcion, 100), 1, now(), null, now())
  on conflict (ip, funcion) do update set
    -- "reinicio": el bloqueo anterior ya venció, o no hubo bloqueo y la ventana pasó.
    fallidos = case
      when (t.bloqueado_hasta is not null and t.bloqueado_hasta <= now())
        or (t.bloqueado_hasta is null and t.primer_fallo <= now() - c_ventana)
      then 1
      else t.fallidos + 1
    end,
    primer_fallo = case
      when (t.bloqueado_hasta is not null and t.bloqueado_hasta <= now())
        or (t.bloqueado_hasta is null and t.primer_fallo <= now() - c_ventana)
      then now()
      else t.primer_fallo
    end,
    bloqueado_hasta = case
      when (t.bloqueado_hasta is not null and t.bloqueado_hasta <= now())
        or (t.bloqueado_hasta is null and t.primer_fallo <= now() - c_ventana)
      then null                                   -- reinicia en 1 (< c_max)
      when t.bloqueado_hasta > now() then t.bloqueado_hasta   -- no se extiende
      when t.fallidos + 1 >= c_max then now() + c_bloqueo
      else null
    end,
    actualizado = now()
  returning t.fallidos, t.bloqueado_hasta into v_fallidos, v_hasta;

  -- Limpieza oportunista (filas sin movimiento hace más de 1 día).
  delete from deposito.pin_intentos where actualizado < now() - interval '1 day';

  return jsonb_build_object(
    'permitido', v_fallidos <= c_max,
    'espera', case when v_fallidos > c_max and v_hasta is not null
                   then greatest(1, ceil(extract(epoch from (v_hasta - now())))::integer)
                   else 0 end
  );
end;
$$;

-- El PIN era correcto: devuelve el intento reservado (y saca el bloqueo si
-- quedó por debajo del máximo). No borra la fila: los fallos previos siguen
-- contando dentro de la ventana.
create or replace function deposito.pin_intento_ok(p_ip text, p_funcion text)
returns void
language sql
security definer
set search_path = ''
as $$
  update deposito.pin_intentos
     set fallidos = greatest(fallidos - 1, 0),
         bloqueado_hasta = case when greatest(fallidos - 1, 0) < 5 then null else bloqueado_hasta end,
         actualizado = now()
   where ip = left(p_ip, 100) and funcion = left(p_funcion, 100);
$$;

revoke all on function deposito.pin_reservar_intento(text, text) from public, anon, authenticated;
revoke all on function deposito.pin_intento_ok(text, text) from public, anon, authenticated;
grant execute on function deposito.pin_reservar_intento(text, text) to service_role;
grant execute on function deposito.pin_intento_ok(text, text) to service_role;
