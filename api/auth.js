// ================================================================
// SECUREVAULT — Backend API (Vercel Serverless Functions)
// Archivo: api/auth.js
// ================================================================
// Instalar dependencias:  npm install @supabase/supabase-js
// Variables de entorno necesarias:
//   SUPABASE_URL          → https://xxxx.supabase.co
//   SUPABASE_SERVICE_KEY  → service_role key
// ================================================================

const { createClient } = require('@supabase/supabase-js');

// ── Cliente Supabase ──────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY  // service_role key (no la anon)
);

// ── CORS helper ───────────────────────────────────────────────
function cors(res) {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

// ── Generar código OTP de 6 dígitos ──────────────────────────
function genOTP() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// ================================================================
// HANDLER PRINCIPAL
// ================================================================
module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ error: 'Método no permitido' });

  const { accion } = req.body;

  // ────────────────────────────────────────────────────────────
  // ACCIÓN 1: LOGIN — validar email + contraseña
  // ────────────────────────────────────────────────────────────
  if (accion === 'login') {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email y contraseña requeridos' });

    const { data: usuario, error } = await supabase
      .from('usuarios')
      .select('id, nombre, email, telefono, activo, password')
      .eq('email', email.toLowerCase().trim())
      .single();

    if (error || !usuario)
      return res.status(401).json({ error: 'Usuario no encontrado' });

    if (!usuario.activo)
      return res.status(403).json({ error: 'Cuenta desactivada' });

    if (usuario.password !== password)
      return res.status(401).json({ error: 'Contraseña incorrecta' });

    return res.json({
      ok: true,
      usuario: {
        id:            usuario.id,
        nombre:        usuario.nombre,
        email:         usuario.email,
        telefono:      usuario.telefono,
        tieneTelefono: false  // SMS desactivado
      }
    });
  }

  // ────────────────────────────────────────────────────────────
  // ACCIÓN 2: ENVIAR OTP (solo email)
  // ────────────────────────────────────────────────────────────
  if (accion === 'enviar_otp') {
    const { usuarioId, metodo } = req.body;
    if (!usuarioId || !metodo)
      return res.status(400).json({ error: 'Datos incompletos' });

    // Solo se acepta método email
    if (metodo !== 'email')
      return res.status(400).json({ error: 'Solo se admite verificación por email' });

    // Obtener usuario
    const { data: usuario } = await supabase
      .from('usuarios')
      .select('id, email, nombre')
      .eq('id', usuarioId)
      .single();

    if (!usuario)
      return res.status(404).json({ error: 'Usuario no encontrado' });

    // Invalidar OTPs anteriores del mismo usuario
    await supabase
      .from('otp_codes')
      .update({ usado: true })
      .eq('usuario_id', usuarioId)
      .eq('usado', false);

    const codigo = genOTP();
    const expira = new Date(Date.now() + 10 * 60 * 1000); // 10 minutos

    // Guardar OTP en la base de datos
    const { error: errInsert } = await supabase
      .from('otp_codes')
      .insert({ usuario_id: usuarioId, codigo, metodo: 'email', expira_en: expira.toISOString() });

    if (errInsert)
      return res.status(500).json({ error: 'Error al guardar código' });

    // Devolver el código al frontend para que EmailJS lo envíe
    return res.json({
      ok:      true,
      metodo:  'email',
      destino: usuario.email,
      codigo   // EmailJS lo envía desde el frontend
    });
  }

  // ────────────────────────────────────────────────────────────
  // ACCIÓN 3: VERIFICAR OTP
  // ────────────────────────────────────────────────────────────
  if (accion === 'verificar_otp') {
    const { usuarioId, codigo } = req.body;
    if (!usuarioId || !codigo)
      return res.status(400).json({ error: 'Datos incompletos' });

    const { data: otp } = await supabase
      .from('otp_codes')
      .select('id, codigo, expira_en, usado')
      .eq('usuario_id', usuarioId)
      .eq('usado', false)
      .order('creado_en', { ascending: false })
      .limit(1)
      .single();

    if (!otp)
      return res.status(401).json({ error: 'Código no encontrado o ya usado' });

    if (new Date() > new Date(otp.expira_en))
      return res.status(401).json({ error: 'El código ha expirado. Solicita uno nuevo.' });

    if (otp.codigo !== codigo)
      return res.status(401).json({ error: 'Código incorrecto' });

    // Marcar como usado
    await supabase.from('otp_codes').update({ usado: true }).eq('id', otp.id);

    return res.json({ ok: true, mensaje: 'Verificación exitosa' });
  }

  return res.status(400).json({ error: 'Acción no reconocida' });
};
