require('dotenv').config();
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const PDFDocument = require('pdfkit');
const { z } = require('zod');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProd = process.env.NODE_ENV === 'production';
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required.');
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) throw new Error('SESSION_SECRET must be at least 32 characters.');

const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 10, idleTimeoutMillis: 30000, ssl: isProd ? { rejectUnauthorized: false } : undefined });

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false, limit: '50kb' }));
app.use(express.json({ limit: '50kb' }));
app.use(express.static(path.join(__dirname, 'public'), { maxAge: isProd ? '1d' : 0 }));
app.set('trust proxy', 1);
app.use(session({
  store: new pgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'physio.sid',
  cookie: { httpOnly: true, sameSite: 'lax', secure: isProd, maxAge: 1000 * 60 * 60 * 8 }
}));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many login attempts. Please try again later.' } });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: true, legacyHeaders: false });

const patientSchema = z.object({
  fullName: z.string().trim().min(2).max(120),
  phone: z.string().trim().min(7).max(20),
  age: z.coerce.number().int().min(0).max(120).optional().or(z.literal('')),
  gender: z.string().trim().max(30).optional(),
  condition: z.string().trim().max(250).optional(),
  address: z.string().trim().max(500).optional(),
  notes: z.string().trim().max(2000).optional()
});
const receiptSchema = z.object({
  patientId: z.coerce.number().int().positive(),
  service: z.string().trim().min(2).max(160),
  sessions: z.coerce.number().int().min(1).max(100),
  amount: z.coerce.number().min(0).max(10000000),
  paymentMethod: z.enum(['Cash','UPI','Card','Bank Transfer']),
  notes: z.string().trim().max(500).optional()
});
const passwordSchema = z.object({ currentPassword: z.string().min(1), newPassword: z.string().min(10).max(128) });

function requireAuth(req, res, next) {
  if (!req.session.adminId) return res.status(401).json({ error: 'Authentication required.' });
  next();
}
function cleanOptional(v) { return v === '' || v == null ? null : v; }
async function nextReceiptNumber(client) {
  const year = new Date().getFullYear();
  const r = await client.query("SELECT receipt_number FROM receipts WHERE receipt_number LIKE $1 ORDER BY id DESC LIMIT 1", [`PHR-${year}-%`]);
  let n = 1;
  if (r.rows[0]) n = Number(r.rows[0].receipt_number.split('-').pop()) + 1;
  return `PHR-${year}-${String(n).padStart(5,'0')}`;
}

app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.post('/api/login', loginLimiter, async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  try {
    const result = await pool.query('SELECT id, username, password_hash, must_change_password FROM admins WHERE lower(username)=lower($1)', [username]);
    if (!result.rows[0] || !(await bcrypt.compare(password, result.rows[0].password_hash))) return res.status(401).json({ error: 'Invalid username or password.' });
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: 'Unable to create session.' });
      req.session.adminId = result.rows[0].id;
      req.session.username = result.rows[0].username;
      req.session.mustChangePassword = result.rows[0].must_change_password;
      res.json({ username: result.rows[0].username, mustChangePassword: result.rows[0].must_change_password });
    });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Login failed.' }); }
});
app.post('/api/logout', requireAuth, (req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/me', (req,res)=>res.json({ authenticated: !!req.session.adminId, username: req.session.username || null, mustChangePassword: !!req.session.mustChangePassword }));

app.post('/api/change-password', requireAuth, async (req,res)=>{
  const parsed = passwordSchema.safeParse(req.body); if (!parsed.success) return res.status(400).json({error:'New password must be at least 10 characters.'});
  try {
    const r = await pool.query('SELECT password_hash FROM admins WHERE id=$1',[req.session.adminId]);
    if (!r.rows[0] || !(await bcrypt.compare(parsed.data.currentPassword,r.rows[0].password_hash))) return res.status(400).json({error:'Current password is incorrect.'});
    const hash = await bcrypt.hash(parsed.data.newPassword,12);
    await pool.query('UPDATE admins SET password_hash=$1, must_change_password=FALSE, updated_at=NOW() WHERE id=$2',[hash,req.session.adminId]);
    req.session.mustChangePassword = false;
    res.json({ok:true});
  } catch(e){console.error(e);res.status(500).json({error:'Unable to change password.'});}
});

app.use('/api', apiLimiter, requireAuth);
app.get('/api/dashboard', async (req,res)=>{
  try {
    const [p,r,t] = await Promise.all([
      pool.query('SELECT COUNT(*)::int count FROM patients'),
      pool.query('SELECT COUNT(*)::int count, COALESCE(SUM(amount),0)::numeric total FROM receipts'),
      pool.query("SELECT COUNT(*)::int count, COALESCE(SUM(amount),0)::numeric total FROM receipts WHERE issued_at >= CURRENT_DATE")
    ]);
    res.json({ patients:p.rows[0], receipts:r.rows[0], today:t.rows[0] });
  } catch(e){console.error(e);res.status(500).json({error:'Unable to load dashboard.'});}
});
app.get('/api/patients', async (req,res)=>{
  const q=String(req.query.q||'').trim();
  try { const r=await pool.query(`SELECT id, patient_code, full_name, phone, age, gender, condition, address, notes, created_at FROM patients ${q?'WHERE full_name ILIKE $1 OR phone ILIKE $1 OR patient_code ILIKE $1':''} ORDER BY created_at DESC LIMIT 250`, q?[`%${q}%`]:[]); res.json(r.rows); }
  catch(e){console.error(e);res.status(500).json({error:'Unable to load patients.'});}
});
app.post('/api/patients', async(req,res)=>{
  const p=patientSchema.safeParse(req.body); if(!p.success) return res.status(400).json({error:'Please check the patient fields.'});
  try { const code='PT-'+Date.now().toString(36).toUpperCase(); const r=await pool.query('INSERT INTO patients(patient_code,full_name,phone,age,gender,condition,address,notes) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',[code,p.data.fullName,p.data.phone,cleanOptional(p.data.age),cleanOptional(p.data.gender),cleanOptional(p.data.condition),cleanOptional(p.data.address),cleanOptional(p.data.notes)]); res.status(201).json(r.rows[0]); }
  catch(e){console.error(e);res.status(500).json({error:'Unable to add patient.'});}
});
app.put('/api/patients/:id', async(req,res)=>{
  const p=patientSchema.safeParse(req.body); if(!p.success) return res.status(400).json({error:'Please check the patient fields.'});
  try { const r=await pool.query('UPDATE patients SET full_name=$1,phone=$2,age=$3,gender=$4,condition=$5,address=$6,notes=$7,updated_at=NOW() WHERE id=$8 RETURNING *',[p.data.fullName,p.data.phone,cleanOptional(p.data.age),cleanOptional(p.data.gender),cleanOptional(p.data.condition),cleanOptional(p.data.address),cleanOptional(p.data.notes),req.params.id]); if(!r.rows[0])return res.status(404).json({error:'Patient not found.'}); res.json(r.rows[0]); }
  catch(e){console.error(e);res.status(500).json({error:'Unable to update patient.'});}
});
app.delete('/api/patients/:id', async(req,res)=>{
  try { const r=await pool.query('DELETE FROM patients WHERE id=$1',[req.params.id]); if(!r.rowCount)return res.status(404).json({error:'Patient not found.'}); res.json({ok:true}); }
  catch(e){ if(e.code==='23503')return res.status(409).json({error:'This patient has receipts. Keep the record to preserve financial history.'}); console.error(e);res.status(500).json({error:'Unable to delete patient.'}); }
});
app.get('/api/receipts', async(req,res)=>{
  try { const r=await pool.query(`SELECT r.id,r.receipt_number,r.patient_id,r.service,r.sessions,r.amount,r.payment_method,r.notes,r.issued_at,p.patient_code,p.full_name,p.phone FROM receipts r JOIN patients p ON p.id=r.patient_id ORDER BY r.issued_at DESC LIMIT 250`); res.json(r.rows); }
  catch(e){console.error(e);res.status(500).json({error:'Unable to load receipts.'});}
});
app.post('/api/receipts', async(req,res)=>{
  const p=receiptSchema.safeParse(req.body); if(!p.success)return res.status(400).json({error:'Please check the receipt fields.'});
  const client=await pool.connect();
  try { await client.query('BEGIN'); const patient=await client.query('SELECT id FROM patients WHERE id=$1 FOR SHARE',[p.data.patientId]); if(!patient.rows[0]){await client.query('ROLLBACK');return res.status(404).json({error:'Patient not found.'});} const number=await nextReceiptNumber(client); const r=await client.query('INSERT INTO receipts(receipt_number,patient_id,service,sessions,amount,payment_method,notes,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',[number,p.data.patientId,p.data.service,p.data.sessions,p.data.amount,p.data.paymentMethod,cleanOptional(p.data.notes),req.session.adminId]); await client.query('COMMIT'); res.status(201).json(r.rows[0]); }
  catch(e){await client.query('ROLLBACK');console.error(e);res.status(500).json({error:'Unable to create receipt.'});} finally{client.release();}
});
app.delete('/api/receipts/:id', async(req,res)=>{ try{const r=await pool.query('DELETE FROM receipts WHERE id=$1',[req.params.id]);if(!r.rowCount)return res.status(404).json({error:'Receipt not found.'});res.json({ok:true});}catch(e){console.error(e);res.status(500).json({error:'Unable to delete receipt.'});} });

app.get('/api/receipts/:id/pdf', async(req,res)=>{
  try {
    const r=await pool.query(`SELECT r.*,p.patient_code,p.full_name,p.phone,p.age,p.gender,p.address FROM receipts r JOIN patients p ON p.id=r.patient_id WHERE r.id=$1`,[req.params.id]);
    if(!r.rows[0])return res.status(404).send('Receipt not found');
    const x=r.rows[0];
    const doc=new PDFDocument({size:'A4',margin:48});
    res.setHeader('Content-Type','application/pdf'); res.setHeader('Content-Disposition',`inline; filename="${x.receipt_number}.pdf"`); doc.pipe(res);
    const logo=path.join(__dirname,'public','logo.png'); if(fs.existsSync(logo))doc.image(logo,48,42,{fit:[100,70]});
    doc.fontSize(19).fillColor('#123d59').font('Helvetica-Bold').text('PHYSIOTHERAPY HOMECARE &',165,46); doc.text('REHABILITATION CLINIC',165,69);
    doc.fontSize(9).fillColor('#49616f').font('Helvetica').text('By Dr Sai Prasanth',165,94); doc.text('Opp. TTD Kalyana Mandapam, near APSRTC Bus Stand, Vayalpad',165,108); doc.text('+91 76600 32158  •  rehabilitationclinicvld@gmail.com',165,122);
    doc.moveTo(48,145).lineTo(547,145).strokeColor('#66c8c7').lineWidth(2).stroke();
    doc.fontSize(22).fillColor('#123d59').font('Helvetica-Bold').text('PAYMENT RECEIPT',48,165);
    doc.fontSize(10).font('Helvetica').fillColor('#516773').text(`Receipt No: ${x.receipt_number}`,380,170); doc.text(`Date: ${new Date(x.issued_at).toLocaleDateString('en-IN')}`,380,187);
    const boxY=220; doc.roundedRect(48,boxY,499,104,8).fillColor('#f2fbfb').fill(); doc.fillColor('#123d59').font('Helvetica-Bold').fontSize(10).text('PATIENT DETAILS',65,boxY+16); doc.font('Helvetica').fillColor('#334b57').fontSize(10).text(`Patient ID: ${x.patient_code}`,65,boxY+37); doc.text(`Name: ${x.full_name}`,65,boxY+54); doc.text(`Phone: ${x.phone}`,65,boxY+71); doc.text(`Age / Gender: ${x.age||'-'} / ${x.gender||'-'}`,340,boxY+37); doc.text(`Address: ${x.address||'-'}`,340,boxY+54,{width:185});
    const tableY=350; doc.fillColor('#123d59').font('Helvetica-Bold').fontSize(10).text('SERVICE',65,tableY); doc.text('SESSIONS',300,tableY); doc.text('AMOUNT',430,tableY); doc.moveTo(65,368).lineTo(530,368).strokeColor('#d4e4e8').stroke(); doc.fillColor('#263f4b').font('Helvetica').fontSize(11).text(x.service,65,387,{width:215}); doc.text(String(x.sessions),300,387); doc.text(`₹ ${Number(x.amount).toLocaleString('en-IN',{minimumFractionDigits:2})}`,430,387); doc.moveTo(65,420).lineTo(530,420).strokeColor('#d4e4e8').stroke(); doc.font('Helvetica-Bold').fontSize(13).fillColor('#123d59').text('TOTAL PAID',300,442); doc.text(`₹ ${Number(x.amount).toLocaleString('en-IN',{minimumFractionDigits:2})}`,430,442);
    doc.font('Helvetica').fontSize(10).fillColor('#526b76').text(`Payment method: ${x.payment_method}`,65,470); if(x.notes)doc.text(`Notes: ${x.notes}`,65,490,{width:465});
    doc.fontSize(9).fillColor('#71848c').text('Thank you for choosing our clinic. This receipt confirms payment received for the service listed above.',65,610,{width:465}); doc.moveTo(390,705).lineTo(525,705).strokeColor('#9db2b9').stroke(); doc.fontSize(9).text('Authorized Signature',410,714); doc.fontSize(8).text('Computer-generated receipt',65,750);
    doc.end();
  } catch(e){console.error(e);res.status(500).send('Unable to generate PDF');}
});

app.get('/health',async(req,res)=>{try{await pool.query('SELECT 1');res.json({ok:true});}catch(e){res.status(503).json({ok:false});}});
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Unexpected server error.'});});

module.exports = app;

if (require.main === module) {
  app.listen(PORT,()=>console.log(`Clinic portal running on http://localhost:${PORT}`));
}
