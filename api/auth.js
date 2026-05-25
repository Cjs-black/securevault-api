// ================================================================
// SECUREVAULT — Backend API (Vercel Serverless Functions)
// Archivo: api/auth.js
// ================================================================
// Instalar dependencias:  npm install @supabase/supabase-js twilio
// ================================================================

const { createClient } = require('@supabase/supabase-js');
const twilio           = require('twilio');

// ── Clientes ──────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY   // service_role key (no la anon)
);

const twilioClient = twilio(
  process.env.TWILIO_SID,
  process.env.TWILIO_TOKEN
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

// ── Validar número peruano ────────────────────────────────────
// Acepta: 9XXXXXXXX (9 dígitos) o +519XXXXXXXX
function esNumeroPe(tel) {
  const limpio = tel.replace(/\s+/g, '');
  return /^(\+51)?9\d{8}$/.test(limpio);
}

function formatearPe(tel) {
  const limpio = tel.replace(/\s+/g, '').replace(/^51/, '');
  if (limpio.startsWith('+51')) return limpio;
  if (limpio.startsWith('9') && limpio.length === 9) return '+51' + limpio;
  return null;
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

    // Comparación directa (en producción real usar bcrypt)
    if (usuario.password !== password)
      return res.status(401).json({ error: 'Contraseña incorrecta' });

    return res.json({
      ok: true,
      usuario: {
        id:       usuario.id,
        nombre:   usuario.nombre,
        email:    usuario.email,
        telefono: usuario.telefono,
        tieneTelefono: !!usuario.telefono
      }
    });
  }

  // ────────────────────────────────────────────────────────────
  // ACCIÓN 2: ENVIAR OTP
  // ────────────────────────────────────────────────────────────
  if (accion === 'enviar_otp') {
    const { usuarioId, metodo, telefonoCustom } = req.body;
    if (!usuarioId || !metodo)
      return res.status(400).json({ error: 'Datos incompletos' });

    // Obtener usuario
    const { data: usuario } = await supabase
      .from('usuarios')
      .select('id, email, telefono, nombre')
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

    const codigo   = genOTP();
    const expira   = new Date(Date.now() + 10 * 60 * 1000); // 10 minutos

    // Guardar OTP en la base de datos
    const { error: errInsert } = await supabase
      .from('otp_codes')
      .insert({ usuario_id: usuarioId, codigo, metodo, expira_en: expira.toISOString() });

    if (errInsert)
      return res.status(500).json({ error: 'Error al guardar código' });

    // ── Enviar según método ──
    if (metodo === 'sms') {
      const telRaw = telefonoCustom || usuario.telefono;
      if (!telRaw)
        return res.status(400).json({ error: 'El usuario no tiene número de celular registrado' });

      if (!esNumeroPe(telRaw))
        return res.status(400).json({ error: 'Solo se aceptan números peruanos (+51 9XXXXXXXX)' });

      const telFormato = formatearPe(telRaw);
      try {
        await twilioClient.messages.create({
          body: `SecureVault: Tu código de verificación es ${codigo}. Válido 10 min. No lo compartas.`,
          from: process.env.TWILIO_FROM,
          to:   telFormato
        });
      } catch (e) {
        return res.status(500).json({ error: 'Error al enviar SMS: ' + e.message });
      }
      return res.json({ ok: true, metodo: 'sms', destino: telFormato.replace(/(\+51)(\d{3})(\d{3})(\d{3})/, '+51 $2 $3 $4') });
    }

    if (metodo === 'email') {
      // Usamos EmailJS desde el frontend; aquí solo confirmamos que el OTP fue guardado
      // Alternativamente puedes usar nodemailer o Resend aquí
      return res.json({
        ok:      true,
        metodo:  'email',
        destino: usuario.email,
        codigo   // Lo enviaremos desde el frontend vía EmailJS
                 // Quita esta línea en producción real y usa nodemailer/Resend
      });
    }

    return res.status(400).json({ error: 'Método inválido' });
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
