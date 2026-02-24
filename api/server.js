const APP_TIMEZONE = 'Asia/Hong_Kong';
process.env.TZ = APP_TIMEZONE;

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const nodemailer = require('nodemailer');
const { stringify } = require('csv-stringify/sync');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// ===== Config =====
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const pool = new Pool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'case_study_leave'
});

pool.on('connect', (client) => {
  client.query(`SET TIME ZONE '${APP_TIMEZONE}'`).catch((error) => {
    console.error('Failed to set PostgreSQL session timezone:', error.message);
  });
});

async function ensureRuntimeSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS calendar_day_remarks (
      date DATE PRIMARY KEY,
      remark TEXT NOT NULL,
      created_by VARCHAR(255) REFERENCES employees(email) ON DELETE SET NULL,
      updated_by VARCHAR(255) REFERENCES employees(email) ON DELETE SET NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_calendar_day_remarks_date
    ON calendar_day_remarks(date)
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS leave_request_id_counters (
      staff_code VARCHAR(20) NOT NULL,
      request_date DATE NOT NULL,
      last_sequence INT NOT NULL DEFAULT 0,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (staff_code, request_date),
      CONSTRAINT chk_leave_request_id_counter_non_negative CHECK (last_sequence >= 0)
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_leave_request_id_counters_date
    ON leave_request_id_counters(request_date)
  `);
}

const SUPERADMIN_EMAIL = 'it@example.com';

// ===== Multer =====
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || '');
    cb(null, crypto.randomBytes(16).toString('hex') + ext);
  }
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

// ===== Helpers =====
function auth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

function isSuperAdminUser(user) {
  return !!user && String(user.email || '').toLowerCase() === SUPERADMIN_EMAIL;
}

function generateTemporaryPassword(length = 12) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%';
  const bytes = crypto.randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i++) {
    out += chars[bytes[i] % chars.length];
  }
  return out;
}

async function getEmployeePasswordPolicy(email) {
  const r = await pool.query(
    `SELECT
       e.email,
       e.staff_code,
       e.department,
       e.location,
       COALESCE(ss.is_office_staff, true) AS is_office_staff
     FROM employees e
     LEFT JOIN staff_settings ss ON ss.employee_email = e.email
     WHERE LOWER(e.email) = $1
     LIMIT 1`,
    [String(email || '').trim().toLowerCase()]
  );
  if (r.rows.length === 0) return null;
  const row = r.rows[0];
  const locationText = String(row.location || '').toLowerCase();
  const deptText = String(row.department || '').toLowerCase();
  const staffCode = String(row.staff_code || '').toUpperCase();
  const isRetailByStaffFlag = row.is_office_staff === false;
  const isRetailByText = locationText.includes('retail') || deptText.includes('retail') || staffCode.startsWith('RT');
  return {
    ...row,
    is_retail_password_blocked: Boolean(isRetailByStaffFlag || isRetailByText)
  };
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin' && req.user.role !== 'superadmin') {
    audit(req.user.email, 'FORBIDDEN_ADMIN', `Tried ${req.method} ${req.path}`).catch(e => console.error('Audit error:', e));
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

function requireApproverOrAdmin(req, res, next) {
  if (req.user.role !== 'approver' && req.user.role !== 'admin' && req.user.role !== 'superadmin') {
    audit(req.user.email, 'FORBIDDEN_APPROVER', `Tried ${req.method} ${req.path}`).catch(e => console.error('Audit error:', e));
    return res.status(403).json({ error: 'Approver access required' });
  }
  next();
}

async function audit(userEmail, action, details, req = null) {
  try {
    // Extract IP and User Agent if req is provided
    let ipAddress = null;
    let userAgent = null;
    
    if (req) {
      ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress || null;
      userAgent = req.headers['user-agent'] || null;
    }
    
    const normalizedUserEmail = String(userEmail || '').trim().toLowerCase() === 'system'
      ? null
      : (userEmail || null);

    await pool.query(
      'INSERT INTO audit_logs (user_email, action, details, ip_address, user_agent) VALUES ($1,$2,$3,$4,$5)',
      [normalizedUserEmail, action, details || '', ipAddress, userAgent]
    );
  } catch (e) {
    console.error('Audit log error:', e);
  }
}

function round2(value) {
  return Math.round((Number(value) || 0) * 100) / 100;
}

function calculateSingleDayLeaveUnits(startDurationType, endDurationType) {
  const start = String(startDurationType || 'FULL').toUpperCase();
  const end = String(endDurationType || 'FULL').toUpperCase();

  if (start === 'FULL' && end === 'FULL') return 1;
  if (start === 'AM' && end === 'PM') return 1;
  return 0.5;
}

function parseBooleanLike(value, fallback = false) {
  if (typeof value === 'boolean') return value;
  const text = String(value ?? '').trim().toLowerCase();
  if (!text) return fallback;
  if (['true', '1', 'yes', 'y', 'on'].includes(text)) return true;
  if (['false', '0', 'no', 'n', 'off'].includes(text)) return false;
  return fallback;
}

function toDateOnly(value) {
  if (!value) return null;
  if (typeof value === 'string') {
    const raw = value.trim();
    const m = raw.match(/^(\d{4})-(\d{2})-(\d{2})$/);
    if (m) {
      const year = Number(m[1]);
      const month = Number(m[2]);
      const day = Number(m[3]);
      const local = new Date(year, month - 1, day);
      if (!Number.isNaN(local.getTime())) return local;
    }
  }
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  return new Date(d.getFullYear(), d.getMonth(), d.getDate());
}

function formatDateOnlyYYYYMMDD(value) {
  if (!value) return '';
  if (typeof value === 'string') {
    const raw = value.trim();
    if (!raw) return '';
    if (/^\d{13}$/.test(raw)) {
      const msDate = new Date(Number(raw));
      if (!Number.isNaN(msDate.getTime())) {
        const y = msDate.getFullYear();
        const m = String(msDate.getMonth() + 1).padStart(2, '0');
        const d = String(msDate.getDate()).padStart(2, '0');
        return `${y}-${m}-${d}`;
      }
    }
    if (/^\d{10}$/.test(raw)) {
      const secDate = new Date(Number(raw) * 1000);
      if (!Number.isNaN(secDate.getTime())) {
        const y = secDate.getFullYear();
        const m = String(secDate.getMonth() + 1).padStart(2, '0');
        const d = String(secDate.getDate()).padStart(2, '0');
        return `${y}-${m}-${d}`;
      }
    }
    if (/^\d{4}-\d{2}-\d{2}/.test(raw)) return raw.slice(0, 10);
  }
  if (value instanceof Date && !Number.isNaN(value.getTime())) {
    const y = value.getFullYear();
    const m = String(value.getMonth() + 1).padStart(2, '0');
    const d = String(value.getDate()).padStart(2, '0');
    return `${y}-${m}-${d}`;
  }
  const dateOnly = toDateOnly(value);
  if (!dateOnly) return '';
  const y = dateOnly.getFullYear();
  const m = String(dateOnly.getMonth() + 1).padStart(2, '0');
  const d = String(dateOnly.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

function formatDateTimeYYYYMMDDHHmmss(value) {
  if (!value) return '';
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return '';
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  const ss = String(d.getSeconds()).padStart(2, '0');
  return `${y}-${m}-${day} ${hh}:${mm}:${ss}`;
}

function daysInYear(year) {
  return new Date(year, 1, 29).getMonth() === 1 ? 366 : 365;
}

function getProRatedALAsOfDate(annualBase, hireDate, asOfDate) {
  const asOf = toDateOnly(asOfDate);
  if (!asOf) return 0;

  const year = asOf.getFullYear();
  const yearStart = new Date(year, 0, 1);
  const hire = toDateOnly(hireDate);
  const accrualStart = hire && hire > yearStart ? hire : yearStart;
  if (accrualStart > asOf) return 0;

  const elapsedDays = Math.floor((asOf - accrualStart) / 86400000);
  const entitled = (Number(annualBase) || 0) * (elapsedDays / daysInYear(year));
  return round2(entitled);
}

function getProRatedALDeltaForDate(annualBase, hireDate, asOfDate) {
  const asOf = toDateOnly(asOfDate);
  if (!asOf) return 0;
  const currentEntitled = getProRatedALAsOfDate(annualBase, hireDate, asOf);
  const prevDate = new Date(asOf);
  prevDate.setDate(prevDate.getDate() - 1);
  const prevEntitled = prevDate.getFullYear() === asOf.getFullYear()
    ? getProRatedALAsOfDate(annualBase, hireDate, prevDate)
    : 0;
  return round2(currentEntitled - prevEntitled);
}



function leaveTypeToBalanceColumn(type) {
  const t = String(type || '').toUpperCase();
  const map = {
    AL: 'balance_al',
    BL: 'balance_bl',
    CL: 'balance_cl',
    CPL: 'balance_cpl',
    DC: 'balance_dc',
    ML: 'balance_ml',
    PL: 'balance_pl',
    SL: 'balance_sl'
  };
  return map[t] || null;
}

const DEFAULT_APPROVED_LEAVE_ADMIN_DELETE_WINDOW_DAYS = 14;
const JAN1_RESET_SETTING_DEFAULTS = {
  jan1_reset_bl_enabled: 'true',
  jan1_reset_cl_enabled: 'false',
  jan1_reset_cpl_enabled: 'false',
  jan1_reset_dc_enabled: 'false',
  jan1_reset_ml_enabled: 'false',
  jan1_reset_pl_enabled: 'false',
  jan1_reset_sl_enabled: 'false'
};

function parseApprovedLeaveDeleteWindowDays(rawValue) {
  const parsed = Number.parseInt(String(rawValue ?? ''), 10);
  if (!Number.isFinite(parsed)) return DEFAULT_APPROVED_LEAVE_ADMIN_DELETE_WINDOW_DAYS;
  if (parsed < 0) return 0;
  if (parsed > 365) return 365;
  return parsed;
}

function normalizeBooleanSettingValue(rawValue, defaultValue = 'false') {
  const text = String(rawValue ?? '').trim().toLowerCase();
  if (!text) return defaultValue;
  if (['true', '1', 'yes', 'y', 'on'].includes(text)) return 'true';
  if (['false', '0', 'no', 'n', 'off'].includes(text)) return 'false';
  return defaultValue;
}

async function canAccessLeaveRequest(user, requestId) {
  try {
    const r = await pool.query(
      'SELECT employee_email FROM leave_requests WHERE id = $1',
      [requestId]
    );
    
    if (r.rows.length === 0) return false;
    
    const requestOwner = r.rows[0].employee_email;
    
    // Admin can see all
    if (user.role === 'admin' || user.role === 'superadmin') return true;
    
    // Owner can ALWAYS see their own (regardless of status)
    if (user.email === requestOwner) return true;
    
    // Approver can see their team's requests
    if (user.role === 'approver') {
      const teamCheck = await pool.query(
        'SELECT 1 FROM employees WHERE email = $1 AND manager_email = $2',
        [requestOwner, user.email]
      );
      return teamCheck.rows.length > 0;
    }
    
    return false;
  } catch (e) {
    console.error('canAccessLeaveRequest error:', e);
    return false;
  }
}

// Generate custom request ID: STAFFCODE-YYYYMMDD-XXX
async function generateRequestId(employeeEmail) {
  try {
    const allocationRes = await pool.query(
      `WITH employee AS (
         SELECT UPPER(TRIM(staff_code)) AS staff_code
         FROM employees
         WHERE email = $1
           AND staff_code IS NOT NULL
           AND BTRIM(staff_code) <> ''
         LIMIT 1
       ),
       next_counter AS (
         INSERT INTO leave_request_id_counters (staff_code, request_date, last_sequence)
         SELECT staff_code, CURRENT_DATE, 1
         FROM employee
         ON CONFLICT (staff_code, request_date)
         DO UPDATE
           SET last_sequence = leave_request_id_counters.last_sequence + 1,
               updated_at = CURRENT_TIMESTAMP
         RETURNING staff_code, request_date, last_sequence
       )
       SELECT
         staff_code,
         TO_CHAR(request_date, 'YYYYMMDD') AS date_str,
         last_sequence
       FROM next_counter`,
      [employeeEmail]
    );

    if (allocationRes.rows.length === 0 || !allocationRes.rows[0].staff_code) {
      throw new Error('Employee staff code not found');
    }

    const row = allocationRes.rows[0];
    const requestId = `${row.staff_code}-${row.date_str}-${String(Number(row.last_sequence) || 1).padStart(3, '0')}`;
    return requestId;
  } catch (e) {
    console.error('Generate request ID error:', e);
    throw e;
  }
}

// Calculate working days
async function calculateWorkingDays(startDate, endDate, startDurationType, endDurationType, employeeEmail) {
  const s = new Date(startDate + 'T00:00:00');
  const e = new Date(endDate + 'T00:00:00');
  
  let skipWeekendHoliday = false;
  if (employeeEmail) {
    const staffRes = await pool.query(
      'SELECT is_office_staff FROM staff_settings WHERE employee_email = $1',
      [employeeEmail]
    );
    skipWeekendHoliday = staffRes.rows.length === 0 || staffRes.rows[0].is_office_staff === true;
  } else {
    skipWeekendHoliday = true;
  }
  
  let holidayDates = new Set();
  if (skipWeekendHoliday) {
    const hRes = await pool.query(`SELECT TO_CHAR(date, 'YYYY-MM-DD') AS date_str FROM holidays`);
    holidayDates = new Set(hRes.rows.map(r => r.date_str));
  }

  let days = 0;
  
  if (startDate === endDate) {
    const dayOfWeek = s.getDay();
    const dateStr = formatDateOnlyYYYYMMDD(s);
    
    if (skipWeekendHoliday) {
      const isWeekend = dayOfWeek === 0 || dayOfWeek === 6;
      const isHoliday = holidayDates.has(dateStr);
      if (isWeekend || isHoliday) {
        days = 0;
      } else {
        days = calculateSingleDayLeaveUnits(startDurationType, endDurationType);
      }
    } else {
      days = calculateSingleDayLeaveUnits(startDurationType, endDurationType);
    }
  } else {
    let totalDays = 0;
    const allDays = [];
    
    let current = new Date(s);
    while (current <= e) {
      const dateStr = formatDateOnlyYYYYMMDD(current);
      const dayOfWeek = current.getDay();
      
      let shouldCount = true;
      
      if (skipWeekendHoliday) {
        const isWeekend = dayOfWeek === 0 || dayOfWeek === 6;
        const isHoliday = holidayDates.has(dateStr);
        shouldCount = !isWeekend && !isHoliday;
      }
      
      if (shouldCount) {
        allDays.push({
          dateStr: dateStr,
          isStart: dateStr === startDate,
          isEnd: dateStr === endDate
        });
      }
      
      current.setDate(current.getDate() + 1);
    }
    
    if (allDays.length === 0) {
      days = 0;
    } else if (allDays.length === 1) {
      const day = allDays[0];
      if (day.isStart && day.isEnd) {
        totalDays = calculateSingleDayLeaveUnits(startDurationType, endDurationType);
      } else if (day.isStart) {
        totalDays = startDurationType === 'FULL' ? 1 : 0.5;
      } else if (day.isEnd) {
        totalDays = endDurationType === 'FULL' ? 1 : 0.5;
      } else {
        totalDays = 1;
      }
    } else {
      for (let i = 0; i < allDays.length; i++) {
        const day = allDays[i];
        
        if (i === 0) {
          totalDays += startDurationType === 'FULL' ? 1 : 0.5;
        } else if (i === allDays.length - 1) {
          totalDays += endDurationType === 'FULL' ? 1 : 0.5;
        } else {
          totalDays += 1;
        }
      }
    }
    
    days = totalDays;
  }
  
  return Math.max(0, days);
}

async function getSMTPConfig() {
  const r = await pool.query('SELECT * FROM smtp_config WHERE is_enabled = true LIMIT 1');
  return r.rows.length > 0 ? r.rows[0] : null;
}

async function sendEmail(to, subject, body, options = {}) {
  const emailType = String(options.emailType || 'approval_request').trim() || 'approval_request';
  const leaveRequestId = options.leaveRequestId ? String(options.leaveRequestId).trim() : null;
  try {
    const config = await getSMTPConfig();
    if (!config) {
      console.warn('SMTP not configured');
      await pool.query(
        'INSERT INTO email_logs (to_email, subject, email_type, leave_request_id, status) VALUES ($1, $2, $3, $4, $5)',
        [to, subject, emailType, leaveRequestId, 'skipped_no_smtp']
      );
      return false;
    }
    
    const port = Number(config.port) || 587;
    const rawBody = String(body || '');
    const htmlBody = rawBody.replace(/\n/g, '<br>');
    const textBody = rawBody.includes('<')
      ? rawBody
          .replace(/<br\s*\/?>/gi, '\n')
          .replace(/<[^>]+>/g, '')
      : rawBody;
    const fromAddress = config.from_email;

    const transporter = nodemailer.createTransport({
      host: config.host,
      port,
      auth: config.use_auth ? { user: config.username, pass: config.password } : false,
      secure: port === 465,
      connectionTimeout: Number(process.env.SMTP_CONNECTION_TIMEOUT_MS || 5000),
      greetingTimeout: Number(process.env.SMTP_GREETING_TIMEOUT_MS || 5000),
      socketTimeout: Number(process.env.SMTP_SOCKET_TIMEOUT_MS || 10000)
    });
    
    await transporter.sendMail({
      from: fromAddress,
      to: to,
      subject: subject,
      text: textBody,
      html: htmlBody
    });
    
    await pool.query(
      'INSERT INTO email_logs (to_email, subject, email_type, leave_request_id, status, sent_at) VALUES ($1, $2, $3, $4, $5, NOW())',
      [to, subject, emailType, leaveRequestId, 'sent']
    );
    return true;
  } catch (e) {
    console.error('Email error:', e);
    await pool.query(
      'INSERT INTO email_logs (to_email, subject, email_type, leave_request_id, status, error_message) VALUES ($1, $2, $3, $4, $5, $6)',
      [to, subject, emailType, leaveRequestId, 'failed', e.message]
    );
    return false;
  }
}

// ===== Routes =====
app.get('/api/health', (req, res) => {
  res.json({ status: 'API running', timestamp: new Date().toISOString(), version: '1.0' });
});

// --- Login ---
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    
    const emailLower = email.toLowerCase();
    const staffCodeUpper = email.toUpperCase();
    
    const r = await pool.query(
      'SELECT * FROM employees WHERE LOWER(email) = $1 OR UPPER(staff_code) = $2',
      [emailLower, staffCodeUpper]
    );
    
    if (r.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    
    const u = r.rows[0];
    
    if (u.is_inactive) {
      await audit(u.email, 'LOGIN_INACTIVE', 'Attempted login while inactive', req);
      return res.status(403).json({ error: 'Account is inactive' });
    }
    
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    
    const effectiveRole = String(u.email || '').toLowerCase() === SUPERADMIN_EMAIL ? 'superadmin' : u.role;
    const token = jwt.sign({ email: u.email, role: effectiveRole }, process.env.JWT_SECRET, { expiresIn: '24h' });
    
    await audit(u.email, 'Login', '', req);
    res.json({
      token,
      user: {
        email: u.email,
        name: u.name,
        role: effectiveRole,
        location: u.location,
        staffCode: u.staff_code
      }
    });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/forgot-password', async (req, res) => {
  let client = null;
  try {
    const requestedEmail = String((req.body && req.body.email) || '').trim().toLowerCase();
    if (!requestedEmail) return res.status(400).json({ error: 'Email is required.' });

    const smtpConfig = await getSMTPConfig();
    if (!smtpConfig) {
      return res.status(503).json({ error: 'SMTP is not enabled. Please contact IT to recover password.' });
    }

    const employeePolicy = await getEmployeePasswordPolicy(requestedEmail);
    if (!employeePolicy) return res.status(404).json({ error: 'Account not found.' });
    if (employeePolicy.is_retail_password_blocked) {
      return res.status(403).json({ error: 'Retail staff cannot change password in system.' });
    }

    const tempPassword = generateTemporaryPassword(12);
    const newHash = await bcrypt.hash(tempPassword, 10);
    const subject = 'Case Study LMS Password Reset';
    const body =
      'A forgot-password request was completed.\n\n' +
      `Temporary password: ${tempPassword}\n\n` +
      'Please login and change your password immediately in the app.';

    client = await pool.connect();
    await client.query('BEGIN');

    const userRes = await client.query(
      'SELECT email FROM employees WHERE LOWER(email) = $1 LIMIT 1',
      [requestedEmail]
    );
    if (userRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Account not found.' });
    }

    await client.query(
      'UPDATE employees SET password_hash = $1, updated_at = NOW() WHERE LOWER(email) = $2',
      [newHash, requestedEmail]
    );

    const sent = await sendEmail(requestedEmail, subject, body, { emailType: 'password_reset' });
    if (!sent) {
      await client.query('ROLLBACK');
      return res.status(500).json({ error: 'Failed to send reset email. Password was not changed.' });
    }

    await client.query('COMMIT');
    await audit(requestedEmail, 'FORGOT_PASSWORD', 'Temporary password sent by email', req);
    res.json({ success: true, message: 'Temporary password sent to your email.' });
  } catch (e) {
    if (client) {
      try { await client.query('ROLLBACK'); } catch (_) {}
    }
    console.error('Forgot-password error:', e);
    res.status(500).json({ error: e.message });
  } finally {
    if (client) client.release();
  }
});

app.post('/api/change-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'currentPassword and newPassword required' });
    if (String(newPassword).length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });

    const policy = await getEmployeePasswordPolicy(req.user.email);
    if (!policy) return res.status(404).json({ error: 'User not found' });
    if (policy.is_retail_password_blocked) {
      return res.status(403).json({ error: 'Retail staff cannot change password in system.' });
    }
    
    const r = await pool.query('SELECT password_hash FROM employees WHERE email = $1', [req.user.email]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    
    const ok = await bcrypt.compare(currentPassword, r.rows[0].password_hash);
    if (!ok) {
      await audit(req.user.email, 'FAILED_PASSWORD_CHANGE', 'Incorrect current password');
      return res.status(401).json({ error: 'Current password incorrect' });
    }
    
    const newHash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE employees SET password_hash = $1, updated_at = NOW() WHERE email = $2', [newHash, req.user.email]);
    await audit(req.user.email, 'Changed password', '');
    res.json({ success: true });
  } catch (e) {
    console.error('Change password error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/user/balance', auth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT email, name, balance_al, balance_al_carry_over, balance_bl, balance_cl, balance_cpl, balance_dc, balance_ml, balance_pl, balance_sl 
       FROM employees WHERE email = $1`,
      [req.user.email]
    );
    
    if (r.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json(r.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/holidays', auth, async (req, res) => {
  try {
    const r = await pool.query(`SELECT TO_CHAR(date, 'YYYY-MM-DD') AS date, name FROM holidays ORDER BY date`);
    res.json(r.rows);
  } catch (e) {
    console.error('Get holidays error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Public holidays for login page calendar preview
app.get('/api/public/holidays', async (req, res) => {
  try {
    const r = await pool.query(`SELECT TO_CHAR(date, 'YYYY-MM-DD') AS date, name FROM holidays ORDER BY date`);
    res.json(r.rows);
  } catch (e) {
    console.error('Get public holidays error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/public/calendar/remarks', async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT
         TO_CHAR(date, 'YYYY-MM-DD') AS date,
         remark
       FROM calendar_day_remarks
       ORDER BY date`
    );
    res.json(r.rows.map((row) => ({
      date: row.date,
      remark: row.remark
    })));
  } catch (e) {
    console.error('Get public calendar remarks error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/calendar/remarks', auth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT
         TO_CHAR(date, 'YYYY-MM-DD') AS date,
         remark,
         created_by,
         updated_by,
         created_at,
         updated_at
       FROM calendar_day_remarks
       ORDER BY date`
    );
    res.json(r.rows.map((row) => ({
      date: row.date,
      remark: row.remark,
      createdBy: row.created_by,
      updatedBy: row.updated_by,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    })));
  } catch (e) {
    console.error('Get calendar remarks error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/admin/calendar/remarks', auth, requireAdmin, async (req, res) => {
  try {
    const { date, remark } = req.body || {};
    const safeDate = String(date || '').trim();
    const safeRemark = String(remark || '').trim();

    if (!safeDate || !safeRemark) {
      return res.status(400).json({ error: 'date and remark are required' });
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(safeDate)) {
      return res.status(400).json({ error: 'Invalid date format (expected YYYY-MM-DD)' });
    }
    if (safeRemark.length > 300) {
      return res.status(400).json({ error: 'Remark cannot exceed 300 characters' });
    }

    const existing = await pool.query(
      `SELECT date
       FROM calendar_day_remarks
       WHERE date = $1`,
      [safeDate]
    );

    if (existing.rows.length === 0) {
      await pool.query(
        `INSERT INTO calendar_day_remarks (date, remark, created_by, updated_by)
         VALUES ($1, $2, $3, $3)`,
        [safeDate, safeRemark, req.user.email]
      );
      await audit(req.user.email, 'ADD_CALENDAR_REMARK', `${safeDate} ${safeRemark.slice(0, 120)}`, req);
    } else {
      await pool.query(
        `UPDATE calendar_day_remarks
         SET remark = $1,
             updated_by = $2,
             updated_at = NOW()
         WHERE date = $3`,
        [safeRemark, req.user.email, safeDate]
      );
      await audit(req.user.email, 'EDIT_CALENDAR_REMARK', `${safeDate} ${safeRemark.slice(0, 120)}`, req);
    }

    const saved = await pool.query(
      `SELECT
         TO_CHAR(date, 'YYYY-MM-DD') AS date,
         remark,
         created_by,
         updated_by,
         created_at,
         updated_at
       FROM calendar_day_remarks
       WHERE date = $1`,
      [safeDate]
    );

    const row = saved.rows[0];
    res.json({
      success: true,
      data: {
        date: row.date,
        remark: row.remark,
        createdBy: row.created_by,
        updatedBy: row.updated_by,
        createdAt: row.created_at,
        updatedAt: row.updated_at
      }
    });
  } catch (e) {
    console.error('Save calendar remark error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/admin/calendar/remarks/:date', auth, requireAdmin, async (req, res) => {
  try {
    const safeDate = String(req.params.date || '').trim();
    if (!safeDate) return res.status(400).json({ error: 'Date is required' });

    const deleted = await pool.query(
      `DELETE FROM calendar_day_remarks
       WHERE date = $1
       RETURNING remark`,
      [safeDate]
    );
    if (deleted.rowCount === 0) {
      return res.status(404).json({ error: 'Calendar remark not found' });
    }

    await audit(req.user.email, 'DELETE_CALENDAR_REMARK', `${safeDate} ${String(deleted.rows[0].remark || '').slice(0, 120)}`, req);
    res.json({ success: true });
  } catch (e) {
    console.error('Delete calendar remark error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/admin/holidays', auth, requireAdmin, async (req, res) => {
  try {
    const r = await pool.query(`SELECT TO_CHAR(date, 'YYYY-MM-DD') AS date, name FROM holidays ORDER BY date DESC`);
    res.json(r.rows);
  } catch (e) {
    console.error('Get admin holidays error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/admin/holidays', auth, requireAdmin, async (req, res) => {
  try {
    const { date, name } = req.body || {};
    const safeDate = String(date || '').trim();
    const safeName = String(name || '').trim();
    if (!safeDate || !safeName) {
      return res.status(400).json({ error: 'date and name are required' });
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(safeDate)) {
      return res.status(400).json({ error: 'Invalid date format (expected YYYY-MM-DD)' });
    }

    await pool.query(`INSERT INTO holidays (date, name) VALUES ($1, $2)`, [safeDate, safeName]);
    await audit(req.user.email, 'ADD_HOLIDAY', `${safeDate} ${safeName}`, req);
    res.json({ success: true });
  } catch (e) {
    if (String(e.message || '').includes('duplicate key')) {
      return res.status(409).json({ error: 'Holiday date already exists' });
    }
    console.error('Add holiday error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/admin/holidays/:date', auth, requireAdmin, async (req, res) => {
  try {
    const oldDate = String(req.params.date || '').trim();
    const { date, name } = req.body || {};
    const newDate = String(date || '').trim();
    const newName = String(name || '').trim();
    if (!oldDate || !newDate || !newName) {
      return res.status(400).json({ error: 'old date, new date and name are required' });
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(newDate)) {
      return res.status(400).json({ error: 'Invalid date format (expected YYYY-MM-DD)' });
    }

    const existing = await pool.query('SELECT date FROM holidays WHERE date = $1', [oldDate]);
    if (existing.rows.length === 0) return res.status(404).json({ error: 'Holiday not found' });

    await pool.query(`UPDATE holidays SET date = $1, name = $2 WHERE date = $3`, [newDate, newName, oldDate]);
    await audit(req.user.email, 'EDIT_HOLIDAY', `${oldDate} -> ${newDate} ${newName}`, req);
    res.json({ success: true });
  } catch (e) {
    if (String(e.message || '').includes('duplicate key')) {
      return res.status(409).json({ error: 'Target holiday date already exists' });
    }
    console.error('Edit holiday error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/admin/holidays/:date', auth, requireAdmin, async (req, res) => {
  try {
    const date = String(req.params.date || '').trim();
    if (!date) return res.status(400).json({ error: 'Date is required' });

    const result = await pool.query(`DELETE FROM holidays WHERE date = $1`, [date]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Holiday not found' });

    await audit(req.user.email, 'DELETE_HOLIDAY', date, req);
    res.json({ success: true });
  } catch (e) {
    console.error('Delete holiday error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/calculate-working-days', auth, async (req, res) => {
  try {
    const { startdate, enddate, startdurationtype, enddurationtype } = req.body;
    
    if (!startdate) {
      return res.status(400).json({ error: 'Start date required' });
    }
    
    const days = await calculateWorkingDays(
      startdate,
      enddate || startdate,
      startdurationtype || 'FULL',
      enddurationtype || 'FULL',
      req.user.email
    );
    
    res.json({ days });
  } catch (e) {
    console.error('Calculate days error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/leave-requests', auth, async (req, res) => {
  try {
    const rawLimit = Number.parseInt(String(req.query.limit || ''), 10);
    const hasLimit = Number.isFinite(rawLimit) && rawLimit > 0;
    const safeLimit = hasLimit ? Math.min(rawLimit, 500) : null;
    const sql = hasLimit
      ? `SELECT id, type, start_date, end_date, start_duration_type, end_duration_type, 
              days, status, remarks, manager_notes, submitted_at, approved_by, approved_at, documents 
         FROM leave_requests 
         WHERE employee_email = $1 
         ORDER BY submitted_at DESC
         LIMIT $2`
      : `SELECT id, type, start_date, end_date, start_duration_type, end_duration_type, 
              days, status, remarks, manager_notes, submitted_at, approved_by, approved_at, documents 
         FROM leave_requests 
         WHERE employee_email = $1 
         ORDER BY submitted_at DESC`;
    const params = hasLimit ? [req.user.email, safeLimit] : [req.user.email];
    const r = await pool.query(
      sql,
      params
    );
    res.json(r.rows);
  } catch (e) {
    console.error('Get requests error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/leave-requests/:id', auth, async (req, res) => {
  try {
    const id = req.params.id;
    if (!id) return res.status(400).json({ error: 'Invalid request id' });
    
    const ok = await canAccessLeaveRequest(req.user, id);
    if (!ok) {
      await audit(req.user.email, 'FORBIDDEN_VIEW', `Tried to view request ${id}`);
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const r = await pool.query(
      `SELECT lr.*, e.name as employee_name,
              e.balance_al AS employee_balance_al,
              e.balance_al_carry_over AS employee_balance_al_carry_over,
              e.balance_bl AS employee_balance_bl,
              e.balance_cl AS employee_balance_cl,
              e.balance_cpl AS employee_balance_cpl,
              e.balance_dc AS employee_balance_dc,
              e.balance_ml AS employee_balance_ml,
              e.balance_pl AS employee_balance_pl,
              e.balance_sl AS employee_balance_sl
       FROM leave_requests lr
       JOIN employees e ON lr.employee_email = e.email
       WHERE lr.id = $1`,
      [id]
    );
    
    if (r.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    const row = r.rows[0];
    const leaveType = String(row.type || '').toUpperCase();

    let remainingBalanceForType = null;
    let remainingBalanceBreakdown = null;
    if (leaveType === 'AL') {
      const regular = parseFloat(row.employee_balance_al) || 0;
      const carryOver = parseFloat(row.employee_balance_al_carry_over) || 0;
      const total = round2(regular + carryOver);
      remainingBalanceForType = total;
      remainingBalanceBreakdown = {
        regular,
        carryOver,
        total
      };
    } else {
      const map = {
        BL: 'employee_balance_bl',
        CL: 'employee_balance_cl',
        CPL: 'employee_balance_cpl',
        DC: 'employee_balance_dc',
        ML: 'employee_balance_ml',
        PL: 'employee_balance_pl',
        SL: 'employee_balance_sl'
      };
      const key = map[leaveType];
      if (key) {
        remainingBalanceForType = parseFloat(row[key]) || 0;
      }
    }

    res.json({
      ...row,
      remaining_balance_for_type: remainingBalanceForType,
      remaining_balance_breakdown: remainingBalanceBreakdown
    });
  } catch (e) {
    console.error('Get request error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/leave-requests', auth, async (req, res) => {
  try {
    const { type, startDate, endDate, startDurationType, endDurationType, remarks, hasAttachment, attachmentCount } = req.body || {};
    
    if (!type || !startDate) return res.status(400).json({ error: 'type and startDate required' });
    const normalizedType = String(type || '').toUpperCase();
    const allowedLeaveTypes = new Set(['AL', 'BL', 'CL', 'CPL', 'DC', 'ML', 'PL', 'SL', 'OTHER']);
    if (!allowedLeaveTypes.has(normalizedType)) {
      return res.status(400).json({ error: `Invalid leave type: ${normalizedType || type}` });
    }
    
    const empRow = await pool.query('SELECT is_inactive, staff_code, name FROM employees WHERE email = $1', [req.user.email]);
    if (empRow.rows.length === 0) {
      return res.status(404).json({ error: 'Employee not found' });
    }
    
    if (empRow.rows[0].is_inactive) {
      return res.status(403).json({ error: 'Cannot submit leave request: Account is inactive' });
    }
    
    if (!empRow.rows[0].staff_code) {
      return res.status(400).json({ error: 'Staff code not set. Please contact admin.' });
    }
    
    const end = endDate || startDate;
    const startDateObj = toDateOnly(startDate);
    const endDateObj = toDateOnly(end);
    if (!startDateObj || !endDateObj) {
      return res.status(400).json({ error: 'Invalid startDate or endDate format' });
    }
    if (endDateObj < startDateObj) {
      return res.status(400).json({ error: 'End date cannot be earlier than start date' });
    }
    const employeeName = empRow.rows[0].name || req.user.email;
    const days = await calculateWorkingDays(startDate, end, startDurationType || 'FULL', endDurationType || 'FULL', req.user.email);
    if (!Number.isFinite(days) || days <= 0) {
      return res.status(400).json({ error: 'Invalid leave duration. Requested range has no working days.' });
    }

    if (normalizedType === 'BL') {
      // BL policy: user can request up to 1.0 day total per calendar year, half-day is allowed.
      if (!Number.isFinite(days) || days <= 0) {
        return res.status(400).json({ error: 'Invalid BL request duration' });
      }
      if (days > 1) {
        return res.status(400).json({ error: 'Birthday Leave cannot exceed 1 day per request' });
      }

      const leaveYear = Number.parseInt(String(startDate || '').slice(0, 4), 10);
      if (!Number.isFinite(leaveYear)) {
        return res.status(400).json({ error: 'Invalid startDate for BL request' });
      }

      const blUsageRes = await pool.query(
        `SELECT COALESCE(SUM(days), 0) AS used_days
         FROM leave_requests
         WHERE employee_email = $1
           AND UPPER(type) = 'BL'
           AND status IN ('pending', 'approved')
           AND EXTRACT(YEAR FROM start_date) = $2`,
        [req.user.email, leaveYear]
      );
      const usedDays = round2(parseFloat(blUsageRes.rows[0]?.used_days) || 0);
      const totalAfterSubmit = round2(usedDays + days);
      if (totalAfterSubmit > 1) {
        return res.status(400).json({
          error: `Birthday Leave yearly limit exceeded. Already requested ${usedDays} day(s) in ${leaveYear}. Maximum is 1 day per year (half-day allowed).`
        });
      }
    }
    
    const staffRes = await pool.query('SELECT is_office_staff FROM staff_settings WHERE employee_email = $1', [req.user.email]);
    const isOfficeStaff = staffRes.rows.length > 0 ? staffRes.rows[0].is_office_staff : true;
    
    const requestId = await generateRequestId(req.user.email);
    
    const rr = await pool.query(
      `INSERT INTO leave_requests (id, employee_email, type, start_date, end_date, start_duration_type, end_duration_type, days, remarks, retail_workflow) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) 
       RETURNING id, employee_email, type, days, retail_workflow`,
      [requestId, req.user.email, normalizedType, startDate, end, startDurationType || 'FULL', endDurationType || 'FULL', days, remarks || '', !isOfficeStaff]
    );
    
    const lr = rr.rows[0];
    const remarksText = (remarks || '').toString().trim() || '-';
    const attachmentCountNumber = Number(attachmentCount) || 0;
    const hasAttachmentFlag = hasAttachment === true || hasAttachment === 'true' || attachmentCountNumber > 0;
    const attachmentText = hasAttachmentFlag ? 'Y' : 'N';
    
    let emailTo = '';
    let emailSubject = '';
    let emailBody = '';
    
    const autoEmailFooter = '\n\n<i>Do not reply this auto-email.</i>';

    if (!isOfficeStaff) {
      emailTo = 'leave@example.com';
      emailSubject = `Leave Request Review Required - ${lr.id} - ${employeeName}`;
      emailBody = `Request ID: ${lr.id}\nEmployee: ${employeeName} (${req.user.email})\nType: ${normalizedType}\nStart Date: ${startDate}\nEnd Date: ${end}\nDays: ${days}\nRemarks: ${remarksText}\nAttachment: ${attachmentText}\n\nPlease review and approve/reject this request in the system.${autoEmailFooter}`;
    } else {
      const mgrRes = await pool.query('SELECT manager_email FROM employees WHERE email = $1', [req.user.email]);
      if (mgrRes.rows.length > 0 && mgrRes.rows[0].manager_email) {
        emailTo = mgrRes.rows[0].manager_email;
        emailSubject = `Leave Request Approval Needed - ${lr.id} - ${employeeName}`;
        emailBody = `Request ID: ${lr.id}\nEmployee: ${employeeName} (${req.user.email})\nType: ${normalizedType}\nStart Date: ${startDate}\nEnd Date: ${end}\nDays: ${days}\nRemarks: ${remarksText}\nAttachment: ${attachmentText}\n\nPlease approve or reject this request in the system.${autoEmailFooter}`;
      }
    }
    
    let emailAttempted = false;
    let emailSent = false;
    let emailFailureReason = '';
    if (emailTo) {
      emailAttempted = true;
      emailSent = await sendEmail(emailTo, emailSubject, emailBody, {
        emailType: 'approval_request',
        leaveRequestId: lr.id
      });
      if (!emailSent) {
        emailFailureReason = 'smtp_send_failed';
      }
    } else {
      emailFailureReason = 'recipient_not_configured';
    }
    
    if (!emailSent) {
      await audit(
        req.user.email,
        'LEAVE_EMAIL_FAILED',
        `Request ${lr.id}, Recipient: ${emailTo || '-'}, Reason: ${emailFailureReason}`,
        req
      );
    }
    
    await audit(req.user.email, 'Submit leave request', `Request ${lr.id}, Type: ${normalizedType}, Days: ${days}`);
    res.json({
      success: true,
      requestId: lr.id,
      emailAttempted,
      emailSent,
      emailRecipient: emailTo || null,
      emailFailureReason: emailFailureReason || null
    });
  } catch (e) {
    console.error('Submit leave request error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/leave-requests/:id', auth, async (req, res) => {
  let client = null;
  try {
    const id = req.params.id;
    const { action, managerNotes } = req.body;

    if (!id) return res.status(400).json({ error: 'Invalid request id' });
    if (!action || !['approve', 'reject'].includes(action)) {
      return res.status(400).json({ error: 'Action must be approve or reject' });
    }

    if (req.user.role !== 'approver' && req.user.role !== 'admin' && req.user.role !== 'superadmin') {
      return res.status(403).json({ error: 'Only approvers and admins can approve/reject requests' });
    }

    client = await pool.connect();
    await client.query('BEGIN');

    const requestQuery = await client.query('SELECT * FROM leave_requests WHERE id = $1 FOR UPDATE', [id]);
    if (requestQuery.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Request not found' });
    }

    const request = requestQuery.rows[0];

    if (request.status !== 'pending') {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Request already processed' });
    }

    if (req.user.role === 'approver') {
      const teamCheck = await client.query(
        'SELECT 1 FROM employees WHERE email = $1 AND manager_email = $2',
        [request.employee_email, req.user.email]
      );
      if (teamCheck.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(403).json({ error: 'You can only approve/reject requests from your team' });
      }
    }

    const newStatus = action === 'approve' ? 'approved' : 'rejected';

    const statusUpdate = await client.query(
      `UPDATE leave_requests
       SET status = $1, approved_by = $2, approved_at = NOW(), manager_notes = $3, updated_at = NOW()
       WHERE id = $4 AND status = 'pending'
       RETURNING id`,
      [newStatus, req.user.email, managerNotes || null, id]
    );
    if (statusUpdate.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Request was processed by another user. Refresh and try again.' });
    }

    if (request.retail_workflow) {
      await client.query(
        `UPDATE leave_requests
         SET hr_reviewed = true, hr_reviewed_by = $1, hr_reviewed_at = NOW(), updated_at = NOW()
         WHERE id = $2`,
        [req.user.email, id]
      );
    }

    let postCommitEmails = [];
    let auditEntries = [];

    if (action === 'approve') {
      const leaveType = request.type.toUpperCase();

      if (leaveType === 'AL') {
        const daysToDeduct = parseFloat(request.days);

        const empBalanceQuery = await client.query(
          'SELECT balance_al, balance_al_carry_over FROM employees WHERE email = $1',
          [request.employee_email]
        );

        if (empBalanceQuery.rows.length > 0) {
          const currentCarryOver = Math.max(0, parseFloat(empBalanceQuery.rows[0].balance_al_carry_over) || 0);
          const currentAL = parseFloat(empBalanceQuery.rows[0].balance_al) || 0;

          let deductFromCarryOver = 0;
          let deductFromRegularAL = 0;

          if (currentCarryOver >= daysToDeduct) {
            deductFromCarryOver = daysToDeduct;
          } else if (currentCarryOver > 0) {
            deductFromCarryOver = currentCarryOver;
            deductFromRegularAL = daysToDeduct - currentCarryOver;
          } else {
            deductFromRegularAL = daysToDeduct;
          }

          const newCarryOver = Math.max(0, currentCarryOver - deductFromCarryOver);
          // Allow negative AL balance when approved days exceed current balance.
          const newAL = round2(currentAL - deductFromRegularAL);

          await client.query(
            `UPDATE employees
             SET balance_al = $1, balance_al_carry_over = $2, updated_at = NOW()
             WHERE email = $3`,
            [newAL, newCarryOver, request.employee_email]
          );

          const deductionDetails = `Approved AL request ${id}: ${daysToDeduct} days. ` +
            `Deducted ${deductFromCarryOver.toFixed(1)} from carry over (${currentCarryOver} -> ${newCarryOver.toFixed(1)}), ` +
            `${deductFromRegularAL.toFixed(1)} from regular AL (${currentAL} -> ${newAL.toFixed(1)})`;

          auditEntries.push({ action: 'APPROVE_AL_SMART_DEDUCT', details: deductionDetails });
        }
      } else {
        const balanceColumn = leaveTypeToBalanceColumn(leaveType);

        if (balanceColumn) {
          if (leaveType === 'BL') {
            const blRes = await client.query(
              'SELECT balance_bl FROM employees WHERE email = $1 LIMIT 1',
              [request.employee_email]
            );
            const currentBL = blRes.rows.length > 0 ? (parseFloat(blRes.rows[0].balance_bl) || 0) : 0;
            const requestedDays = parseFloat(request.days) || 0;
            const deductedDays = Math.min(Math.max(currentBL, 0), requestedDays);
            const newBL = round2(Math.max(0, currentBL - requestedDays));

            await client.query(
              `UPDATE employees SET balance_bl = $1, updated_at = NOW() WHERE email = $2`,
              [newBL, request.employee_email]
            );

            auditEntries.push({
              action: 'APPROVE_BL_FLOOR',
              details: `Request ${id} (BL) by ${request.employee_email}: Requested ${requestedDays} day(s), Deducted ${round2(deductedDays)} day(s), Balance ${currentBL} -> ${newBL}`
            });
          } else {
            await client.query(
              `UPDATE employees SET ${balanceColumn} = ${balanceColumn} - $1, updated_at = NOW() WHERE email = $2`,
              [request.days, request.employee_email]
            );

            auditEntries.push({
              action: 'APPROVE',
              details: `Request ${id} (${leaveType}) by ${request.employee_email}: ${request.days} days deducted`
            });
          }
        } else {
          auditEntries.push({
            action: 'APPROVE',
            details: `Request ${id} (${leaveType}) by ${request.employee_email}: No balance deduction`
          });
        }
      }

      if (request.retail_workflow) {
        const retailMeta = await client.query(
          'SELECT supervisor_email FROM staff_settings WHERE employee_email = $1 LIMIT 1',
          [request.employee_email]
        );

        const supervisorEmail = retailMeta.rows.length > 0 ? retailMeta.rows[0].supervisor_email : null;

        if (supervisorEmail) {
          const subject = `Retail Leave Approved - ${id}`;
          const body = `Employee ${request.employee_email} leave request ${id} is approved. Type: ${request.type}, Days: ${request.days}.`;
          postCommitEmails.push({ to: supervisorEmail, subject, body, emailType: 'leave_status_update', leaveRequestId: id });

          await client.query(
            `UPDATE leave_requests
             SET supervisor_notified = true, supervisor_notified_at = NOW(), updated_at = NOW()
             WHERE id = $1`,
            [id]
          );
        }
      } else {
        const subject = `Leave Request Approved - ${id}`;
        const body = `Your leave request ${id} has been approved. Type: ${request.type}, Days: ${request.days}.`;
        postCommitEmails.push({ to: request.employee_email, subject, body, emailType: 'leave_status_update', leaveRequestId: id });
      }
    } else {
      auditEntries.push({ action: 'REJECT', details: `Request ${id} by ${request.employee_email}` });

      const subject = `Leave Request Rejected - ${id}`;
      const reasonText = managerNotes ? ` Reason: ${managerNotes}` : '';
      const body = `Your leave request ${id} has been rejected.${reasonText}`;
      postCommitEmails.push({ to: request.employee_email, subject, body, emailType: 'leave_status_update', leaveRequestId: id });
    }

    await client.query('COMMIT');

    for (const entry of auditEntries) {
      await audit(req.user.email, entry.action, entry.details, req);
    }

    for (const msg of postCommitEmails) {
      await sendEmail(msg.to, msg.subject, msg.body, {
        emailType: msg.emailType,
        leaveRequestId: msg.leaveRequestId
      });
    }

    res.json({
      success: true,
      message: `Request ${newStatus}`,
      requestId: id,
      status: newStatus
    });
  } catch (e) {
    console.error('Update request error:', e);
    if (client) {
      try { await client.query('ROLLBACK'); } catch (_) {}
    }
    res.status(500).json({ error: e.message });
  } finally {
    if (client) client.release();
  }
});
app.delete('/api/leave-requests/:id', auth, async (req, res) => {
  let client;
  let postCommitEmail = null;
  try {
    const id = req.params.id;
    if (!id) return res.status(400).json({ error: 'Invalid request id' });

    const cancelReason = String((req.body || {}).cancelReason || '').trim();
    const isAdminActor = req.user.role === 'admin' || req.user.role === 'superadmin';
    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress || null;
    const userAgent = req.headers['user-agent'] || null;

    client = await pool.connect();
    await client.query('BEGIN');

    const requestQuery = await client.query(
      'SELECT * FROM leave_requests WHERE id = $1 FOR UPDATE',
      [id]
    );

    if (requestQuery.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Request not found' });
    }

    const request = requestQuery.rows[0];
    const isAdminDeletingOthers = isAdminActor && request.employee_email !== req.user.email;
    const leaveType = String(request.type || '').toUpperCase();
    let approvedCreditSummary = '';

    if (!isAdminActor) {
      if (request.employee_email !== req.user.email) {
        await client.query('ROLLBACK');
        return res.status(403).json({ error: 'You can only delete your own pending requests' });
      }
      if (request.status !== 'pending') {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'You can only delete pending requests. Contact admin to cancel approved leave.' });
      }
    }

    const addAuditWithinTransaction = async (action, details) => {
      await client.query(
        'INSERT INTO audit_logs (user_email, action, details, ip_address, user_agent) VALUES ($1,$2,$3,$4,$5)',
        [req.user.email || null, action, details || '', ipAddress, userAgent]
      );
    };

    if (request.status === 'approved') {
      if (!isAdminActor) {
        await client.query('ROLLBACK');
        return res.status(403).json({ error: 'Only admin can cancel approved leave requests' });
      }

      if (cancelReason.length < 3) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Cancellation reason is required (minimum 3 characters)' });
      }

      const settingRes = await client.query(
        `SELECT setting_value
         FROM system_settings
         WHERE setting_key = 'approved_leave_admin_delete_window_days'
         LIMIT 1`
      );
      const rawWindowSetting = settingRes.rows.length > 0
        ? settingRes.rows[0].setting_value
        : DEFAULT_APPROVED_LEAVE_ADMIN_DELETE_WINDOW_DAYS;
      const deleteWindowDays = parseApprovedLeaveDeleteWindowDays(rawWindowSetting);

      if (deleteWindowDays > 0) {
        const approvedAt = request.approved_at ? new Date(request.approved_at) : null;
        if (!approvedAt || Number.isNaN(approvedAt.getTime())) {
          await client.query('ROLLBACK');
          return res.status(400).json({ error: 'Approved request is missing processed timestamp and cannot be cancelled' });
        }
        const elapsedDays = (Date.now() - approvedAt.getTime()) / 86400000;
        if (elapsedDays > deleteWindowDays) {
          await client.query('ROLLBACK');
          return res.status(400).json({
            error: `Approved leave can only be cancelled within ${deleteWindowDays} days after approval`
          });
        }
      }

      let daysToCredit = parseFloat(request.days) || 0;

      if (leaveType === 'AL') {
        let creditCarryOver = 0;
        let creditRegular = daysToCredit;

        const auditRes = await client.query(
          `SELECT details
           FROM audit_logs
           WHERE action = 'APPROVE_AL_SMART_DEDUCT'
             AND details ILIKE $1
           ORDER BY created_at DESC
           LIMIT 1`,
          [`%Approved AL request ${id}:%`]
        );

        if (auditRes.rows.length > 0) {
          const details = String(auditRes.rows[0].details || '');
          const match = details.match(/Deducted\s+([0-9.]+)\s+from carry over.*?,\s*([0-9.]+)\s+from regular AL/i);
          if (match) {
            const parsedCarry = parseFloat(match[1]) || 0;
            const parsedRegular = parseFloat(match[2]) || 0;
            const totalParsed = parsedCarry + parsedRegular;

            if (totalParsed > 0) {
              const scale = daysToCredit / totalParsed;
              creditCarryOver = round2(parsedCarry * scale);
              creditRegular = round2(parsedRegular * scale);

              const drift = round2(daysToCredit - (creditCarryOver + creditRegular));
              if (drift !== 0) {
                creditRegular = round2(creditRegular + drift);
              }
            }
          }
        }

        await client.query(
          `UPDATE employees
           SET balance_al = balance_al + $1,
               balance_al_carry_over = balance_al_carry_over + $2,
               updated_at = NOW()
           WHERE email = $3`,
          [creditRegular, creditCarryOver, request.employee_email]
        );

        await addAuditWithinTransaction(
          'DELETE_APPROVED_AL',
          `Cancelled approved AL request ${id} for ${request.employee_email}. Credited back ${creditCarryOver.toFixed(1)} to carry over and ${creditRegular.toFixed(1)} to AL. Reason: ${cancelReason}`
        );
        approvedCreditSummary = `${creditCarryOver.toFixed(1)} day(s) to AL carry over and ${creditRegular.toFixed(1)} day(s) to AL`;
      } else {
        const balanceColumn = leaveTypeToBalanceColumn(leaveType);
        if (leaveType === 'BL') {
          const blAuditRes = await client.query(
            `SELECT details
             FROM audit_logs
             WHERE action = 'APPROVE_BL_FLOOR'
               AND details ILIKE $1
             ORDER BY created_at DESC
             LIMIT 1`,
            [`%Request ${id} (BL)%`]
          );
          if (blAuditRes.rows.length > 0) {
            const details = String(blAuditRes.rows[0].details || '');
            const match = details.match(/Deducted\s+([0-9.]+)\s+day/i);
            if (match) {
              daysToCredit = round2(parseFloat(match[1]) || daysToCredit);
            }
          }
        }

        if (balanceColumn) {
          await client.query(
            `UPDATE employees
             SET ${balanceColumn} = ${balanceColumn} + $1,
                 updated_at = NOW()
             WHERE email = $2`,
            [daysToCredit, request.employee_email]
          );
        }

        await addAuditWithinTransaction(
          'DELETE_APPROVED_REQUEST',
          `Deleted approved request ${id} for ${request.employee_email}. Credited back ${daysToCredit} days of ${leaveType || 'UNKNOWN'}. Reason: ${cancelReason}`
        );
        approvedCreditSummary = `${daysToCredit} day(s) to ${leaveType || 'leave balance'}`;
      }
    } else if (request.status === 'pending') {
      await addAuditWithinTransaction(
        'DELETE_PENDING_REQUEST',
        `Deleted pending request ${id}`
      );
    } else {
      await addAuditWithinTransaction(
        'DELETE_PROCESSED_REQUEST',
        `Deleted ${request.status} request ${id}`
      );
    }

    if (isAdminDeletingOthers) {
      const actionText = request.status === 'approved' ? 'cancelled' : 'deleted';
      const subject = request.status === 'approved'
        ? `Leave Request Cancelled by Admin - ${id}`
        : `Leave Request Deleted by Admin - ${id}`;
      const reasonLine = cancelReason ? `\nReason: ${cancelReason}` : '';
      const creditLine = request.status === 'approved'
        ? `\nBalance credited back: ${approvedCreditSummary || `${request.days} day(s)`}`
        : '';
      const processedAt = formatDateTimeYYYYMMDDHHmmss(new Date());
      const body =
        `Your leave request ${id} has been ${actionText} by admin.\n` +
        `Type: ${request.type}\n` +
        `Start Date: ${formatDateOnlyYYYYMMDD(request.start_date)}\n` +
        `End Date: ${formatDateOnlyYYYYMMDD(request.end_date)}\n` +
        `Days: ${request.days}\n` +
        `${creditLine}${reasonLine}\n` +
        `Processed By: ${req.user.email}\n` +
        `Processed At: ${processedAt}`;
      postCommitEmail = { to: request.employee_email, subject, body };
    }

    await client.query('DELETE FROM leave_requests WHERE id = $1', [id]);
    await client.query('COMMIT');

    try {
      const docs = Array.isArray(request.documents) ? request.documents : [];
      for (const doc of docs) {
        const stored = path.basename(String(doc.storedName || ''));
        if (!stored || stored !== doc.storedName) continue;
        const filePath = path.join(UPLOAD_DIR, stored);
        const resolvedPath = path.resolve(filePath);
        const resolvedUploadDir = path.resolve(UPLOAD_DIR);
        if (!resolvedPath.startsWith(resolvedUploadDir + path.sep)) continue;
        if (fs.existsSync(resolvedPath)) {
          try { fs.unlinkSync(resolvedPath); } catch (_) {}
        }
      }
    } catch (_) {
      // best-effort cleanup
    }

    if (postCommitEmail) {
      setImmediate(async () => {
        try {
          await sendEmail(postCommitEmail.to, postCommitEmail.subject, postCommitEmail.body, {
            emailType: 'leave_status_update'
          });
        } catch (emailErr) {
          console.error('Delete-request email notification error:', emailErr);
        }
      });
    }

    res.json({
      success: true,
      message: request.status === 'approved'
        ? `Approved request cancelled and ${request.days} days credited back to ${request.employee_email}`
        : 'Request deleted successfully',
      emailQueued: Boolean(postCommitEmail)
    });
  } catch (e) {
    console.error('Delete request error:', e);
    if (client) {
      try { await client.query('ROLLBACK'); } catch (_) {}
    }
    res.status(500).json({ error: e.message });
  } finally {
    if (client) client.release();
  }
});


app.get('/api/pending-requests', auth, requireApproverOrAdmin, async (req, res) => {
  try {
    let sql = `
      SELECT lr.id, lr.employee_email, e.name, lr.type, lr.start_date, lr.end_date, 
             lr.start_duration_type, lr.end_duration_type, lr.days, lr.remarks, 
             lr.status, lr.submitted_at, lr.documents, lr.retail_workflow
      FROM leave_requests lr
      JOIN employees e ON lr.employee_email = e.email
      WHERE lr.status = 'pending'
    `;
    const params = [];
    
    if (req.user.role === 'approver') {
      sql += ' AND e.manager_email = $1';
      params.push(req.user.email);
    }
    
    sql += ' ORDER BY lr.submitted_at DESC';
    
    const r = await pool.query(sql, params);
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/leave-requests/:id/documents', auth, upload.array('files', 10), async (req, res) => {
  try {
    const id = req.params.id;
    if (!id) return res.status(400).json({ error: 'Invalid request id' });
    
    const ok = await canAccessLeaveRequest(req.user, id);
    if (!ok) {
      await audit(req.user.email, 'FORBIDDEN_UPLOAD', `Tried to upload documents for request ${id}`);
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const files = req.files || [];
    if (files.length === 0) return res.status(400).json({ error: 'No files uploaded' });
    
    const docs = files.map(f => ({
      originalName: f.originalname,
      storedName: f.filename,
      mimeType: f.mimetype,
      size: f.size,
      uploadedAt: new Date().toISOString()
    }));
    
    await pool.query(
      `UPDATE leave_requests SET documents = COALESCE(documents, '[]'::jsonb) || $1::jsonb, updated_at = NOW() WHERE id = $2`,
      [JSON.stringify(docs), id]
    );
    
    await audit(req.user.email, 'Uploaded documents', `Leave request ${id}: ${docs.length} file(s)`);
    res.json({ success: true, uploaded: docs.length });
  } catch (e) {
    console.error('Upload documents error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/leave-requests/:id/documents', auth, async (req, res) => {
  try {
    const id = req.params.id;
    if (!id) return res.status(400).json({ error: 'Invalid request id' });
    
    const ok = await canAccessLeaveRequest(req.user, id);
    if (!ok) return res.status(403).json({ error: 'Forbidden' });
    
    const r = await pool.query('SELECT documents FROM leave_requests WHERE id = $1', [id]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    
    const docs = r.rows[0].documents || [];
    const out = docs.map(d => ({
      ...d,
      downloadUrl: `/api/leave-requests/${id}/documents/${encodeURIComponent(d.storedName)}`
    }));
    
    res.json(out);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/leave-requests/:id/documents/:storedName', auth, async (req, res) => {
  try {
    const id = req.params.id;
    const storedName = req.params.storedName;
    
    const ok = await canAccessLeaveRequest(req.user, id);
    if (!ok) {
      await audit(req.user.email, 'FORBIDDEN_DOWNLOAD', `Tried to download document for request ${id}`);
      return res.status(403).json({ error: 'Forbidden' });
    }

    const safeStoredName = path.basename(String(storedName || ''));
    if (!safeStoredName || safeStoredName !== storedName) {
      return res.status(400).json({ error: 'Invalid file name' });
    }

    const docRes = await pool.query('SELECT documents FROM leave_requests WHERE id = $1', [id]);
    if (docRes.rows.length === 0) return res.status(404).json({ error: 'Not found' });

    const docs = docRes.rows[0].documents || [];
    const docMatch = docs.find(d => String(d.storedName) === safeStoredName);
    if (!docMatch) return res.status(404).json({ error: 'File not found' });

    const filePath = path.join(UPLOAD_DIR, safeStoredName);
    const resolvedPath = path.resolve(filePath);
    const resolvedUploadDir = path.resolve(UPLOAD_DIR);
    if (!resolvedPath.startsWith(resolvedUploadDir + path.sep)) {
      return res.status(400).json({ error: 'Invalid file path' });
    }
    if (!fs.existsSync(resolvedPath)) return res.status(404).json({ error: 'File not found' });
    
    res.download(resolvedPath, docMatch.originalName || safeStoredName);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/admin/employees', auth, requireAdmin, async (req, res) => {
  try {
    const actorIsSuperAdmin = isSuperAdminUser(req.user) || req.user.role === 'superadmin';
    const filterClause = actorIsSuperAdmin
      ? ''
      : `WHERE e.role <> 'admin' AND LOWER(e.email) <> $1`;
    const params = actorIsSuperAdmin ? [] : [SUPERADMIN_EMAIL];

    const r = await pool.query(
      `SELECT
        e.email, e.name, e.department, e.manager_email, e.location, e.staff_code,
        e.is_inactive, e.role, e.annual_leave_base, e.carry_over_reset_month,
        TO_CHAR(e.hire_date, 'YYYY-MM-DD') AS hire_date,
        e.balance_al, e.balance_al_carry_over, e.balance_bl, e.balance_cl,
        e.balance_cpl, e.balance_dc, e.balance_ml, e.balance_pl, e.balance_sl,
        COALESCE(ss.is_office_staff, true) AS is_office_staff,
        ss.supervisor_email
      FROM employees e
      LEFT JOIN staff_settings ss ON e.email = ss.employee_email
      ${filterClause}
      ORDER BY e.name`
      , params
    );
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/admin/employees', auth, requireAdmin, async (req, res) => {
  try {
    const { email, name, department, managerEmail, location, staffCode, role, isOfficeStaff, hireDate, annualLeaveBase } = req.body || {};
    if (!email || !name) return res.status(400).json({ error: 'Email and name required' });
    if (!staffCode || !String(staffCode).trim()) return res.status(400).json({ error: 'Staff code is required' });
    if (!hireDate) return res.status(400).json({ error: 'Join date (hireDate) is required' });

    const actorIsSuperAdmin = isSuperAdminUser(req.user) || req.user.role === 'superadmin';
    if (role === 'admin' && !actorIsSuperAdmin) {
      return res.status(403).json({ error: 'Only superadmin can assign admin role' });
    }
    const safeEmail = String(email).trim().toLowerCase();
    if (!safeEmail) return res.status(400).json({ error: 'Email is required' });
    if (safeEmail === SUPERADMIN_EMAIL) {
      return res.status(409).json({ error: 'This email is reserved for the superadmin account.' });
    }
    const safeStaffCode = String(staffCode).trim().toUpperCase();
    const existing = await pool.query(
      'SELECT 1 FROM employees WHERE LOWER(email) = $1 OR UPPER(staff_code) = $2 LIMIT 1',
      [safeEmail, safeStaffCode]
    );
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'Email or staff code already exists.' });
    }
    const safeRole = ['employee', 'approver', 'admin'].includes(role) ? role : 'employee';
    const safeHireDate = String(hireDate).slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(safeHireDate)) {
      return res.status(400).json({ error: 'Invalid hire date format (expected YYYY-MM-DD)' });
    }
    const resolvedAnnualLeaveBase = Number(annualLeaveBase ?? 12);
    const initialAL = getProRatedALAsOfDate(resolvedAnnualLeaveBase, safeHireDate, new Date());
    const officeFlag = isOfficeStaff !== undefined
      ? parseBooleanLike(isOfficeStaff, true)
      : !String(location || '').toLowerCase().includes('retail');

    const defaultPassword = `${safeStaffCode}lms`;
    const hash = await bcrypt.hash(defaultPassword, 10);
    await pool.query(
      `INSERT INTO employees (email, name, password_hash, department, manager_email, location, staff_code, role, hire_date, annual_leave_base, balance_al, is_inactive)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, false)`,
      [safeEmail, name, hash, department || '', managerEmail || null, location || '', safeStaffCode || null, safeRole, safeHireDate, resolvedAnnualLeaveBase, initialAL]
    );

    await pool.query(
      `INSERT INTO staff_settings (employee_email, location, supervisor_email, is_office_staff, updated_at)
       VALUES ($1, $2, $3, $4, NOW())`,
      [safeEmail, location || '', managerEmail || null, officeFlag]
    );

    await audit(req.user.email, 'ADD_EMPLOYEE', `${safeEmail}, role=${safeRole}, office=${officeFlag}, hireDate=${safeHireDate}, initialAL=${initialAL}, defaultPassword=staff_code+lms`, req);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});
app.patch('/api/admin/employees/:email/inactive', auth, requireAdmin, async (req, res) => {
  try {
    const { email } = req.params;
    const { is_inactive } = req.body || {};
    
    if (is_inactive === undefined) return res.status(400).json({ error: 'is_inactive required' });

    const targetUser = await pool.query('SELECT role, email FROM employees WHERE email = $1', [email]);
    if (targetUser.rows.length === 0) return res.status(404).json({ error: 'Employee not found' });

    const targetRole = targetUser.rows[0].role;
    const targetEmail = String(targetUser.rows[0].email || '').toLowerCase();
    const actorIsSuperAdmin = isSuperAdminUser(req.user) || req.user.role === 'superadmin';
    if ((targetRole === 'admin' || targetEmail === SUPERADMIN_EMAIL) && !actorIsSuperAdmin) {
      return res.status(403).json({ error: 'Only superadmin can change admin account status' });
    }
    
    await pool.query(
      'UPDATE employees SET is_inactive = $1, updated_at = NOW() WHERE email = $2',
      [is_inactive, email]
    );
    
    await audit(req.user.email, 'Toggle inactive', `${email} -> ${is_inactive}`);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/admin/employees/:email', auth, requireAdmin, async (req, res) => {
  try {
    const targetEmail = String(req.params.email || '').trim().toLowerCase();
    if (!targetEmail) return res.status(400).json({ error: 'Target email required' });

    if (targetEmail === String(req.user.email || '').toLowerCase()) {
      return res.status(400).json({ error: 'You cannot remove your own account' });
    }

    const targetRes = await pool.query('SELECT role, email FROM employees WHERE LOWER(email) = $1 LIMIT 1', [targetEmail]);
    if (targetRes.rows.length === 0) return res.status(404).json({ error: 'Employee not found' });

    const targetRole = String(targetRes.rows[0].role || '').toLowerCase();
    const targetCanonicalEmail = String(targetRes.rows[0].email || '').toLowerCase();
    const actorIsSuperAdmin = isSuperAdminUser(req.user) || req.user.role === 'superadmin';

    if (targetCanonicalEmail === SUPERADMIN_EMAIL) {
      return res.status(403).json({ error: 'Superadmin account cannot be removed' });
    }
    if (targetRole === 'admin' && !actorIsSuperAdmin) {
      return res.status(403).json({ error: 'Only superadmin can remove admin accounts' });
    }

    const leaveHistoryRes = await pool.query(
      'SELECT COUNT(*)::int AS cnt FROM leave_requests WHERE employee_email = $1',
      [targetCanonicalEmail]
    );
    const leaveHistoryCount = leaveHistoryRes.rows[0]?.cnt || 0;
    if (leaveHistoryCount > 0) {
      return res.status(409).json({
        error: 'Cannot hard-delete employee with leave history. Set account inactive instead to preserve records.'
      });
    }

    await pool.query('DELETE FROM employees WHERE LOWER(email) = $1', [targetEmail]);
    await audit(req.user.email, 'DELETE_EMPLOYEE', `Removed ${targetCanonicalEmail}`, req);
    res.json({ success: true, message: `User ${targetCanonicalEmail} removed` });
  } catch (e) {
    console.error('Delete employee error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/admin/smtp-config', auth, requireAdmin, async (req, res) => {
  try {
    if (!isSuperAdminUser(req.user)) {
      await audit(req.user.email, 'FORBIDDEN_SMTP_VIEW', 'Attempted to view SMTP config without superadmin rights', req);
      return res.status(403).json({ error: 'Only superadmin can view SMTP settings. Please contact IT (it@example.com).' });
    }

    const r = await pool.query('SELECT * FROM smtp_config LIMIT 1');
    if (r.rows.length === 0) return res.json(null);
    res.json(r.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/admin/smtp-config', auth, requireAdmin, async (req, res) => {
  try {
    if (!isSuperAdminUser(req.user)) {
      await audit(req.user.email, 'FORBIDDEN_SMTP_UPDATE', 'Attempted to update SMTP config without superadmin rights', req);
      return res.status(403).json({ error: 'Only superadmin can update SMTP settings. Please contact IT (it@example.com).' });
    }

    const { host, port, use_auth, username, password, from_email, is_enabled } = req.body || {};
    
    if (!host || !port || !from_email) return res.status(400).json({ error: 'host, port, and from_email required' });
    
    await pool.query('DELETE FROM smtp_config');
    await pool.query(
      `INSERT INTO smtp_config (host, port, use_auth, username, password, from_email, shared_mailbox, is_enabled, created_by) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [host, port, use_auth || false, username || '', password || '', from_email, from_email, is_enabled || false, req.user.email]
    );
    
    await audit(req.user.email, 'Update SMTP config', `Host: ${host}, Port: ${port}`);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/admin/smtp-test', auth, requireAdmin, async (req, res) => {
  try {
    if (!isSuperAdminUser(req.user)) {
      await audit(req.user.email, 'FORBIDDEN_SMTP_TEST', 'Attempted SMTP test without superadmin rights', req);
      return res.status(403).json({ error: 'Only superadmin can run SMTP tests.' });
    }

    const config = await getSMTPConfig();
    if (!config) {
      return res.status(503).json({ error: 'SMTP is not enabled. Please enable SMTP first.' });
    }

    const toEmail = String((req.body && req.body.to_email) || config.from_email || '').trim();
    if (!toEmail) {
      return res.status(400).json({ error: 'to_email is required' });
    }

    const port = Number(config.port) || 587;
    const subject = 'Case Study LMS SMTP Test';
    const rawBody = 'This is a test email from Case Study LMS SMTP configuration.\n\nIf you received this, SMTP is working.';
    const htmlBody = rawBody.replace(/\n/g, '<br>');
    const textBody = rawBody;

    const transporter = nodemailer.createTransport({
      host: config.host,
      port,
      auth: config.use_auth ? { user: config.username, pass: config.password } : false,
      secure: port === 465,
      connectionTimeout: 5000,
      greetingTimeout: 5000,
      socketTimeout: 5000
    });

    await transporter.sendMail({
      from: config.from_email,
      to: toEmail,
      subject,
      text: textBody,
      html: htmlBody
    });

    await pool.query(
      'INSERT INTO email_logs (to_email, subject, email_type, status, sent_at) VALUES ($1, $2, $3, $4, NOW())',
      [toEmail, subject, 'smtp_test', 'sent']
    );
    await audit(req.user.email, 'SMTP_TEST', `SMTP test email sent to ${toEmail}`, req);
    res.json({ success: true });
  } catch (e) {
    await pool.query(
      'INSERT INTO email_logs (to_email, subject, email_type, status, error_message) VALUES ($1, $2, $3, $4, $5)',
      ['-', 'Case Study LMS SMTP Test', 'smtp_test', 'failed', e.message]
    );
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/reports/:reportType', auth, requireAdmin, async (req, res) => {
  try {
    const rawReportType = String(req.params.reportType || '').trim().toLowerCase();
    const reportTypeAlias = {
      'monthly-individual-approved-leave': 'monthly-individual-approved-leave',
      'monthly-individual-leave-approved': 'monthly-individual-approved-leave',
      'monthly-approved-individual-leave': 'monthly-individual-approved-leave',
      'monthly-approved-leave-individual': 'monthly-individual-approved-leave'
    };
    const reportType = reportTypeAlias[rawReportType] || rawReportType;
    const month = String(req.query.month || '').trim();
    const monthPattern = /^\d{4}-\d{2}$/;
    let csv = '';
    let filename = '';
    const fmt2 = (value) => (Number(value) || 0).toFixed(2);
    
    switch (reportType) {
      case 'leave-balance': {
        const r = await pool.query(
          `SELECT staff_code, email, name, department, annual_leave_base, balance_al, balance_al_carry_over, balance_bl, balance_cl, balance_cpl, balance_dc, balance_ml, balance_pl, balance_sl 
           FROM employees WHERE is_inactive = false ORDER BY name`
        );
        csv = stringify([
          ['Staff Code', 'Email', 'Name', 'Department', 'AL Base', 'AL Balance', 'AL Carry Over', 'BL', 'CL', 'CPL', 'DC', 'ML', 'PL', 'SL'],
          ...r.rows.map(row => [
            row.staff_code || '', row.email, row.name, row.department, row.annual_leave_base,
            fmt2(row.balance_al), fmt2(row.balance_al_carry_over), fmt2(row.balance_bl), fmt2(row.balance_cl), fmt2(row.balance_cpl), fmt2(row.balance_dc), fmt2(row.balance_ml), fmt2(row.balance_pl), fmt2(row.balance_sl)
          ])
        ]);
        filename = 'leave-balance-report.csv';
        break;
      }
      
      case 'leave-history': {
        const r = await pool.query(
          `SELECT lr.id, lr.employee_email, e.staff_code, e.name, lr.type, lr.start_date, lr.end_date, lr.days, lr.status, lr.approved_by, lr.approved_at 
           FROM leave_requests lr 
           JOIN employees e ON lr.employee_email = e.email 
           ORDER BY lr.submitted_at DESC`
        );
        csv = stringify([
          ['Request ID', 'Staff Code', 'Employee Email', 'Employee Name', 'Type', 'Start Date', 'End Date', 'Days', 'Status', 'Approved By', 'Approved Date'],
          ...r.rows.map(row => [
            row.id,
            row.staff_code || '',
            row.employee_email,
            row.name,
            row.type,
            formatDateOnlyYYYYMMDD(row.start_date),
            formatDateOnlyYYYYMMDD(row.end_date),
            row.days,
            row.status,
            row.approved_by || '',
            formatDateTimeYYYYMMDDHHmmss(row.approved_at)
          ])
        ]);
        filename = 'leave-history-report.csv';
        break;
      }

      case 'audit-logs': {
        const r = await pool.query(
          `SELECT id, created_at, user_email, action, details, ip_address, user_agent
           FROM audit_logs
           ORDER BY created_at DESC
           LIMIT 5000`
        );
        csv = stringify([
          ['ID', 'Timestamp', 'User Email', 'Action', 'Details', 'IP Address', 'User Agent'],
          ...r.rows.map(row => [
            row.id,
            formatDateTimeYYYYMMDDHHmmss(row.created_at),
            row.user_email || '',
            row.action || '',
            row.details || '',
            row.ip_address || '',
            row.user_agent || ''
          ])
        ]);
        filename = 'audit-logs-report.csv';
        break;
      }

      case 'leave-usage-summary': {
        const r = await pool.query(
          `SELECT
             e.staff_code,
             e.email,
             e.name,
             e.department,
             e.annual_leave_base,
             e.balance_al,
             e.balance_al_carry_over,
             COALESCE(SUM(CASE WHEN lr.status = 'approved' THEN lr.days ELSE 0 END), 0) AS approved_days_ytd,
             COALESCE(SUM(CASE WHEN lr.status = 'approved' AND lr.type = 'AL' THEN lr.days ELSE 0 END), 0) AS approved_al_days_ytd
           FROM employees e
           LEFT JOIN leave_requests lr
             ON lr.employee_email = e.email
             AND lr.start_date >= date_trunc('year', CURRENT_DATE)
             AND lr.start_date < (date_trunc('year', CURRENT_DATE) + INTERVAL '1 year')
           WHERE e.is_inactive = false
           GROUP BY e.staff_code, e.email, e.name, e.department, e.annual_leave_base, e.balance_al, e.balance_al_carry_over
           ORDER BY e.department, e.name`
        );
        csv = stringify([
          ['Staff Code', 'Email', 'Name', 'Department', 'AL Base', 'Approved AL Days (YTD)', 'Approved Total Leave Days (YTD)', 'Current AL Balance', 'Current Carry Over Balance'],
          ...r.rows.map(row => [
            row.staff_code || '',
            row.email,
            row.name,
            row.department || '',
            row.annual_leave_base,
            row.approved_al_days_ytd,
            row.approved_days_ytd,
            fmt2(row.balance_al),
            fmt2(row.balance_al_carry_over)
          ])
        ]);
        filename = 'leave-usage-summary-ytd.csv';
        break;
      }

      case 'pending-aging': {
        const r = await pool.query(
          `SELECT
             lr.id,
             e.staff_code,
             lr.employee_email,
             e.name,
             e.department,
             lr.type,
             lr.start_date,
             lr.end_date,
             lr.days,
             lr.submitted_at,
             GREATEST(0, (CURRENT_DATE - DATE(lr.submitted_at)))::int AS waiting_days,
             lr.retail_workflow
           FROM leave_requests lr
           JOIN employees e ON e.email = lr.employee_email
           WHERE lr.status = 'pending'
           ORDER BY waiting_days DESC, lr.submitted_at ASC`
        );
        csv = stringify([
          ['Request ID', 'Staff Code', 'Employee Email', 'Employee Name', 'Department', 'Type', 'Start Date', 'End Date', 'Days', 'Submitted At', 'Waiting Days', 'Workflow'],
          ...r.rows.map(row => [
            row.id,
            row.staff_code || '',
            row.employee_email,
            row.name,
            row.department || '',
            row.type,
            formatDateOnlyYYYYMMDD(row.start_date),
            formatDateOnlyYYYYMMDD(row.end_date),
            row.days,
            formatDateTimeYYYYMMDDHHmmss(row.submitted_at),
            row.waiting_days,
            row.retail_workflow ? 'Retail' : 'Office'
          ])
        ]);
        filename = 'pending-requests-aging.csv';
        break;
      }

      case 'monthly-individual-approved-leave': {
        const now = new Date();
        const currentMonth = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
        const targetMonth = monthPattern.test(month) ? month : currentMonth;
        const r = await pool.query(
          `SELECT
             lr.id,
             e.staff_code,
             lr.employee_email,
             e.name,
             e.department,
             lr.type,
             lr.start_date,
             lr.end_date,
             lr.days,
             lr.approved_by,
             lr.approved_at
           FROM leave_requests lr
           JOIN employees e ON e.email = lr.employee_email
           WHERE lr.status = 'approved'
             AND TO_CHAR(lr.approved_at, 'YYYY-MM') = $1
           ORDER BY e.department, e.name, lr.approved_at DESC`,
          [targetMonth]
        );
        csv = stringify([
          ['Month', 'Request ID', 'Staff Code', 'Employee Email', 'Employee Name', 'Department', 'Type', 'Start Date', 'End Date', 'Days', 'Approved By', 'Approved At'],
          ...r.rows.map(row => [
            targetMonth,
            row.id,
            row.staff_code || '',
            row.employee_email,
            row.name || '',
            row.department || '',
            row.type,
            formatDateOnlyYYYYMMDD(row.start_date),
            formatDateOnlyYYYYMMDD(row.end_date),
            row.days,
            row.approved_by || '',
            formatDateTimeYYYYMMDDHHmmss(row.approved_at)
          ])
        ]);
        filename = `monthly-individual-approved-leave-${targetMonth}.csv`;
        break;
      }
      
      default:
        return res.status(400).json({ error: 'Invalid report type' });
    }
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=${filename}`);
    res.send(csv);
    await audit(req.user.email, 'Export report', reportType);
  } catch (e) {
    console.error('Report error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/calendar/leaves', auth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT
         lr.employee_email,
         e.name,
         e.department,
         TO_CHAR(lr.start_date, 'YYYY-MM-DD') AS start_date,
         TO_CHAR(lr.end_date, 'YYYY-MM-DD') AS end_date,
         lr.start_duration_type,
         lr.end_duration_type,
         lr.type,
         COALESCE(lr.retail_workflow, false) AS retail_workflow
       FROM leave_requests lr 
       JOIN employees e ON lr.employee_email = e.email 
       WHERE lr.status = 'approved' AND e.is_inactive = false 
       ORDER BY lr.start_date`
    );
    
    const events = r.rows.map(row => ({
      employee: row.name,
      email: row.employee_email,
      department: row.department,
      type: row.type,
      startDate: row.start_date,
      endDate: row.end_date,
      startDurationType: row.start_duration_type || 'FULL',
      endDurationType: row.end_duration_type || 'FULL',
      isOfficeStaff: !row.retail_workflow
    }));
    
    res.json(events);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Public calendar preview (approved leaves only)
app.get('/api/public/calendar/leaves', async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT
         lr.employee_email,
         e.name,
         e.department,
         TO_CHAR(lr.start_date, 'YYYY-MM-DD') AS start_date,
         TO_CHAR(lr.end_date, 'YYYY-MM-DD') AS end_date,
         lr.start_duration_type,
         lr.end_duration_type,
         lr.type,
         COALESCE(lr.retail_workflow, false) AS retail_workflow
       FROM leave_requests lr 
       JOIN employees e ON lr.employee_email = e.email 
       WHERE lr.status = 'approved' AND e.is_inactive = false 
       ORDER BY lr.start_date`
    );
    
    const events = r.rows.map(row => ({
      employee: row.name,
      email: row.employee_email,
      department: row.department,
      type: row.type,
      startDate: row.start_date,
      endDate: row.end_date,
      startDurationType: row.start_duration_type || 'FULL',
      endDurationType: row.end_duration_type || 'FULL',
      isOfficeStaff: !row.retail_workflow
    }));
    
    res.json(events);
  } catch (e) {
    console.error('Get public calendar leaves error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ===== VIEW AUDIT LOGS =====
app.get('/api/admin/audit-logs', auth, requireAdmin, async (req, res) => {
  try {
    const { limit = 100, offset = 0, action, userEmail, startDate, endDate } = req.query;
    
    let sql = `
      SELECT 
        id,
        user_email,
        action,
        details,
        ip_address,
        user_agent,
        created_at
      FROM audit_logs
      WHERE 1=1
    `;
    
    const params = [];
    let paramCount = 0;
    
    // Filter by action
    if (action) {
      paramCount++;
      sql += ` AND action ILIKE $${paramCount}`;
      params.push(`%${action}%`);
    }
    
    // Filter by user email
    if (userEmail) {
      paramCount++;
      sql += ` AND user_email ILIKE $${paramCount}`;
      params.push(`%${userEmail}%`);
    }
    
    // Filter by date range
    if (startDate) {
      paramCount++;
      sql += ` AND created_at >= $${paramCount}`;
      params.push(startDate);
    }
    
    if (endDate) {
      paramCount++;
      sql += ` AND created_at <= $${paramCount}::date + interval '1 day'`;
      params.push(endDate);
    }
    
    sql += ` ORDER BY created_at DESC`;
    
    // Add pagination
    paramCount++;
    sql += ` LIMIT $${paramCount}`;
    params.push(parseInt(limit));
    
    paramCount++;
    sql += ` OFFSET $${paramCount}`;
    params.push(parseInt(offset));
    
    const result = await pool.query(sql, params);
    
    // Get total count for pagination
    let countSql = 'SELECT COUNT(*) FROM audit_logs WHERE 1=1';
    const countParams = [];
    let countParamCount = 0;
    
    if (action) {
      countParamCount++;
      countSql += ` AND action ILIKE $${countParamCount}`;
      countParams.push(`%${action}%`);
    }
    
    if (userEmail) {
      countParamCount++;
      countSql += ` AND user_email ILIKE $${countParamCount}`;
      countParams.push(`%${userEmail}%`);
    }
    
    if (startDate) {
      countParamCount++;
      countSql += ` AND created_at >= $${countParamCount}`;
      countParams.push(startDate);
    }
    
    if (endDate) {
      countParamCount++;
      countSql += ` AND created_at <= $${countParamCount}::date + interval '1 day'`;
      countParams.push(endDate);
    }
    
    const countResult = await pool.query(countSql, countParams);
    const totalRecords = parseInt(countResult.rows[0].count);
    
    res.json({
      logs: result.rows,
      pagination: {
        total: totalRecords,
        limit: parseInt(limit),
        offset: parseInt(offset),
        hasMore: (parseInt(offset) + parseInt(limit)) < totalRecords
      }
    });
    
  } catch (e) {
    console.error('Get audit logs error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ===== EDIT EMPLOYEE =====
app.put('/api/admin/employees/:email', auth, requireAdmin, async (req, res) => {
  try {
    const { email } = req.params;
    const {
      name,
      department,
      managerEmail,
      location,
      staffCode,
      role,
      isOfficeStaff,
      hireDate,
      annualLeaveBase,
      recalculateAL,
      carryOverResetMonth,
      balanceAl,
      balanceAlCarryOver,
      balanceBl,
      balanceCl,
      balanceCpl,
      balanceDc,
      balanceMl,
      balancePl,
      balanceSl
    } = req.body || {};

    if (!name) return res.status(400).json({ error: 'Name is required' });

    const currentData = await pool.query('SELECT * FROM employees WHERE email = $1', [email]);
    if (currentData.rows.length === 0) {
      return res.status(404).json({ error: 'Employee not found' });
    }

    const oldData = currentData.rows[0];
    const actorIsSuperAdmin = isSuperAdminUser(req.user) || req.user.role === 'superadmin';
    const targetIsSuperAdminEmail = String(oldData.email || '').toLowerCase() === SUPERADMIN_EMAIL;
    if ((oldData.role === 'admin' || String(oldData.email || '').toLowerCase() === SUPERADMIN_EMAIL) && !actorIsSuperAdmin) {
      return res.status(403).json({ error: 'Only superadmin can edit admin account' });
    }
    if (targetIsSuperAdminEmail && role !== undefined && role !== 'admin') {
      return res.status(400).json({ error: 'Superadmin role cannot be changed' });
    }
    if (role === 'admin' && !actorIsSuperAdmin) {
      return res.status(403).json({ error: 'Only superadmin can assign admin role' });
    }
    const safeRole = targetIsSuperAdminEmail
      ? 'admin'
      : (role === undefined
        ? oldData.role
        : (['employee', 'approver', 'admin'].includes(role) ? role : 'employee'));
    const oldHireDate = formatDateOnlyYYYYMMDD(oldData.hire_date);
    const safeHireDate = hireDate === undefined
      ? (oldHireDate || null)
      : (hireDate ? String(hireDate).slice(0, 10) : null);
    if (safeHireDate && !/^\d{4}-\d{2}-\d{2}$/.test(safeHireDate)) {
      return res.status(400).json({ error: 'Invalid hire date format (expected YYYY-MM-DD)' });
    }
    const resolvedAnnualLeaveBase = Number(annualLeaveBase ?? oldData.annual_leave_base ?? 13);
    const hireDateChanged = oldHireDate !== (safeHireDate || '');
    const annualBaseChanged = Number(oldData.annual_leave_base ?? 13) !== Number(resolvedAnnualLeaveBase);
    // Respect caller intent: only recalculate when explicitly requested.
    const shouldAutoRecalculateAL = Boolean(recalculateAL);
    const autoCalculatedAL = shouldAutoRecalculateAL && safeHireDate
      ? getProRatedALAsOfDate(resolvedAnnualLeaveBase, safeHireDate, new Date())
      : null;
    const nextBalanceAl = autoCalculatedAL !== null
      ? autoCalculatedAL
      : (balanceAl ?? oldData.balance_al);

    await pool.query(
      `UPDATE employees SET
        name = $1,
        department = $2,
        manager_email = $3,
        location = $4,
        staff_code = $5,
        role = $6,
        hire_date = $7,
        annual_leave_base = $8,
        carry_over_reset_month = $9,
        balance_al = $10,
        balance_al_carry_over = $11,
        balance_bl = $12,
        balance_cl = $13,
        balance_cpl = $14,
        balance_dc = $15,
        balance_ml = $16,
        balance_pl = $17,
        balance_sl = $18,
        updated_at = NOW()
      WHERE email = $19`,
      [
        name,
        department || '',
        managerEmail || null,
        location || '',
        staffCode || null,
        safeRole,
        safeHireDate,
        resolvedAnnualLeaveBase,
        carryOverResetMonth ?? 10,
        nextBalanceAl,
        balanceAlCarryOver ?? oldData.balance_al_carry_over,
        balanceBl ?? oldData.balance_bl,
        balanceCl ?? oldData.balance_cl,
        balanceCpl ?? oldData.balance_cpl,
        balanceDc ?? oldData.balance_dc,
        balanceMl ?? oldData.balance_ml,
        balancePl ?? oldData.balance_pl,
        balanceSl ?? oldData.balance_sl,
        email
      ]
    );

    const hasStaffSetting = await pool.query(
      'SELECT id, is_office_staff FROM staff_settings WHERE employee_email = $1 ORDER BY id ASC LIMIT 1',
      [email]
    );

    const existingOfficeFlag = hasStaffSetting.rows.length > 0
      ? Boolean(hasStaffSetting.rows[0].is_office_staff)
      : !String(location || oldData.location || '').toLowerCase().includes('retail');
    const officeFlag = isOfficeStaff === undefined
      ? existingOfficeFlag
      : (isOfficeStaff === true || isOfficeStaff === 'true');

    if (hasStaffSetting.rows.length > 0) {
      await pool.query(
        `UPDATE staff_settings
         SET location = $1, supervisor_email = $2, is_office_staff = $3, updated_at = NOW()
         WHERE id = $4`,
        [location || '', managerEmail || null, officeFlag, hasStaffSetting.rows[0].id]
      );
    } else {
      await pool.query(
        `INSERT INTO staff_settings (employee_email, location, supervisor_email, is_office_staff, updated_at)
         VALUES ($1, $2, $3, $4, NOW())`,
        [email, location || '', managerEmail || null, officeFlag]
      );
    }

    const toNum = (v) => Number(v ?? 0);
    const numChanged = (a, b) => Math.abs(toNum(a) - toNum(b)) > 0.0001;
    const fmt2 = (v) => toNum(v).toFixed(2);

    const newName = name;
    const newRole = safeRole;
    const newDepartment = department || '';
    const newLocation = location || '';
    const newManagerEmail = managerEmail || null;
    const newStaffCode = staffCode || null;
    const newCarryOverResetMonth = carryOverResetMonth ?? 10;
    const newBalanceAl = nextBalanceAl;
    const newBalanceAlCarryOver = balanceAlCarryOver ?? oldData.balance_al_carry_over;
    const newBalanceBl = balanceBl ?? oldData.balance_bl;
    const newBalanceCl = balanceCl ?? oldData.balance_cl;
    const newBalanceCpl = balanceCpl ?? oldData.balance_cpl;
    const newBalanceDc = balanceDc ?? oldData.balance_dc;
    const newBalanceMl = balanceMl ?? oldData.balance_ml;
    const newBalancePl = balancePl ?? oldData.balance_pl;
    const newBalanceSl = balanceSl ?? oldData.balance_sl;

    const changes = [];
    if ((oldData.name || '') !== (newName || '')) changes.push(`Name: ${oldData.name || '-'} -> ${newName || '-'}`);
    if ((oldData.role || '') !== (newRole || '')) changes.push(`Role: ${oldData.role || '-'} -> ${newRole || '-'}`);
    if ((oldData.department || '') !== newDepartment) changes.push(`Department: ${oldData.department || '-'} -> ${newDepartment || '-'}`);
    if ((oldData.location || '') !== newLocation) changes.push(`Location: ${oldData.location || '-'} -> ${newLocation || '-'}`);
    if ((oldData.manager_email || null) !== newManagerEmail) changes.push(`Manager Email: ${oldData.manager_email || '-'} -> ${newManagerEmail || '-'}`);
    if ((oldData.staff_code || null) !== newStaffCode) changes.push(`Staff Code: ${oldData.staff_code || '-'} -> ${newStaffCode || '-'}`);
    if (Number(oldData.annual_leave_base ?? 13) !== Number(resolvedAnnualLeaveBase)) {
      changes.push(`Annual Leave Base: ${oldData.annual_leave_base ?? 13} -> ${resolvedAnnualLeaveBase}`);
    }
    if (Number(oldData.carry_over_reset_month ?? 10) !== Number(newCarryOverResetMonth)) {
      changes.push(`Carry Over Reset Month: ${oldData.carry_over_reset_month ?? 10} -> ${newCarryOverResetMonth}`);
    }
    if (oldHireDate !== (safeHireDate || '')) changes.push(`Join Date: ${oldHireDate || '-'} -> ${safeHireDate || '-'}`);

    if (numChanged(oldData.balance_al, newBalanceAl)) {
      const alLabel = autoCalculatedAL !== null ? 'AL (Auto Recalculated)' : 'AL';
      changes.push(`${alLabel}: ${fmt2(oldData.balance_al)} -> ${fmt2(newBalanceAl)}`);
    }
    if (numChanged(oldData.balance_al_carry_over, newBalanceAlCarryOver)) {
      changes.push(`AL Carry Over: ${fmt2(oldData.balance_al_carry_over)} -> ${fmt2(newBalanceAlCarryOver)}`);
    }
    if (numChanged(oldData.balance_bl, newBalanceBl)) {
      changes.push(`BL: ${fmt2(oldData.balance_bl)} -> ${fmt2(newBalanceBl)}`);
    }
    if (numChanged(oldData.balance_cl, newBalanceCl)) {
      changes.push(`CL: ${fmt2(oldData.balance_cl)} -> ${fmt2(newBalanceCl)}`);
    }
    if (numChanged(oldData.balance_cpl, newBalanceCpl)) {
      changes.push(`CPL: ${fmt2(oldData.balance_cpl)} -> ${fmt2(newBalanceCpl)}`);
    }
    if (numChanged(oldData.balance_dc, newBalanceDc)) {
      changes.push(`DC: ${fmt2(oldData.balance_dc)} -> ${fmt2(newBalanceDc)}`);
    }
    if (numChanged(oldData.balance_ml, newBalanceMl)) {
      changes.push(`ML: ${fmt2(oldData.balance_ml)} -> ${fmt2(newBalanceMl)}`);
    }
    if (numChanged(oldData.balance_pl, newBalancePl)) {
      changes.push(`PL: ${fmt2(oldData.balance_pl)} -> ${fmt2(newBalancePl)}`);
    }
    if (numChanged(oldData.balance_sl, newBalanceSl)) {
      changes.push(`SL: ${fmt2(oldData.balance_sl)} -> ${fmt2(newBalanceSl)}`);
    }

    const auditDetails = changes.length > 0
      ? `Updated employee ${email}: ${changes.join(', ')}`
      : `Updated employee ${email}: no detected field deltas`;

    await audit(req.user.email, 'EDIT_EMPLOYEE', auditDetails, req);
    res.json({ success: true, message: 'Employee updated successfully', autoCalculatedAL });
  } catch (e) {
    console.error('Update employee error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/admin/employees/:email/reset-password', auth, requireAdmin, async (req, res) => {
  try {
    if (!isSuperAdminUser(req.user)) {
      await audit(req.user.email, 'FORBIDDEN_RESET_PASSWORD', `Attempted reset for ${req.params.email}`, req);
      return res.status(403).json({ error: 'Only superadmin can reset employee passwords.' });
    }

    const targetEmail = String(req.params.email || '').trim().toLowerCase();
    const { newPassword } = req.body || {};
    if (!targetEmail) return res.status(400).json({ error: 'Target email required.' });
    if (!newPassword || String(newPassword).length < 3) {
      return res.status(400).json({ error: 'New password must be at least 3 characters.' });
    }

    const targetRes = await pool.query(
      'SELECT email FROM employees WHERE LOWER(email) = $1 LIMIT 1',
      [targetEmail]
    );
    if (targetRes.rows.length === 0) return res.status(404).json({ error: 'Employee not found.' });

    const newHash = await bcrypt.hash(String(newPassword), 10);
    await pool.query(
      'UPDATE employees SET password_hash = $1, updated_at = NOW() WHERE LOWER(email) = $2',
      [newHash, targetEmail]
    );

    await audit(req.user.email, 'SUPERADMIN_RESET_PASSWORD', `Reset password for ${targetEmail}`, req);
    res.json({ success: true });
  } catch (e) {
    console.error('Reset employee password error:', e);
    res.status(500).json({ error: e.message });
  }
});
// ===== SYSTEM SETTINGS =====
app.get('/api/admin/system-settings', auth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM system_settings ORDER BY setting_key');
    const settings = {};
    result.rows.forEach(row => {
      settings[row.setting_key] = row.setting_value;
    });
    if (!Object.prototype.hasOwnProperty.call(settings, 'approved_leave_admin_delete_window_days')) {
      settings.approved_leave_admin_delete_window_days = String(DEFAULT_APPROVED_LEAVE_ADMIN_DELETE_WINDOW_DAYS);
    }
    for (const [key, defaultValue] of Object.entries(JAN1_RESET_SETTING_DEFAULTS)) {
      if (!Object.prototype.hasOwnProperty.call(settings, key)) {
        settings[key] = defaultValue;
      }
    }
    res.json(settings);
  } catch (e) {
    console.error('Get system settings error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/admin/system-settings', auth, requireAdmin, async (req, res) => {
  try {
    const { settings } = req.body;
    
    if (!settings || typeof settings !== 'object') {
      return res.status(400).json({ error: 'Settings object required' });
    }
    
    for (const [key, value] of Object.entries(settings)) {
      let safeValue = value;
      if (key === 'approved_leave_admin_delete_window_days') {
        safeValue = String(parseApprovedLeaveDeleteWindowDays(value));
      } else if (Object.prototype.hasOwnProperty.call(JAN1_RESET_SETTING_DEFAULTS, key)) {
        safeValue = normalizeBooleanSettingValue(value, JAN1_RESET_SETTING_DEFAULTS[key]);
      }
      await pool.query(
        `INSERT INTO system_settings (setting_key, setting_value, updated_by, updated_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (setting_key) 
         DO UPDATE SET setting_value = $2, updated_by = $3, updated_at = NOW()`,
        [key, safeValue, req.user.email]
      );
    }
    
    await audit(req.user.email, 'UPDATE_SYSTEM_SETTINGS', `Updated settings: ${Object.keys(settings).join(', ')}`, req);
    
    res.json({ success: true });
  } catch (e) {
    console.error('Update system settings error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ===== SCHEDULED: Check and Expire Carry Over AL =====
async function checkAndExpireCarryOver() {
  try {
    console.log('Running carry over expiration check...');
    
    // Get global settings
    const settingsRes = await pool.query(
      `SELECT setting_key, setting_value FROM system_settings 
       WHERE setting_key IN ('al_carry_over_deadline_month', 'al_carry_over_deadline_day', 'al_carry_over_forfeit_enabled')`
    );
    
    const settings = {};
    settingsRes.rows.forEach(row => {
      settings[row.setting_key] = row.setting_value;
    });
    
    const hardForfeitEnabled = settings.al_carry_over_forfeit_enabled === 'true';
    if (!hardForfeitEnabled) {
      console.log('ℹ️ Carry over hard-forfeit disabled, skipping expiration check');
      return;
    }

    const deadlineMonth = parseInt(settings.al_carry_over_deadline_month || 10);
    const deadlineDay = parseInt(settings.al_carry_over_deadline_day || 31);
    
    // Get current date in Sample Region timezone
    const now = new Date();
    const currentYear = now.getFullYear();
    const currentMonth = now.getMonth() + 1; // 1-12
    const currentDay = now.getDate();
    
    // Check if TODAY is the day AFTER the deadline (expiration day)
    let isExpirationDay = false;
    
    if (currentMonth > deadlineMonth) {
      isExpirationDay = true;
    } else if (currentMonth === deadlineMonth && currentDay > deadlineDay) {
      isExpirationDay = true;
    }
    
    // Only run on the first day after deadline
    if (isExpirationDay) {
      // Check if already ran this period
      const lastExpireCheck = await pool.query(
        `SELECT created_at FROM audit_logs 
         WHERE action = 'CARRY_OVER_EXPIRED' 
         AND created_at >= $1
         LIMIT 1`,
        [`${currentYear}-${deadlineMonth.toString().padStart(2,'0')}-${deadlineDay.toString().padStart(2,'0')}`]
      );
      
      if (lastExpireCheck.rows.length > 0) {
        console.log('⏭️ Carry over already expired this period, skipping');
        return;
      }
      
      // Expire all carry over balances
      const expireResult = await pool.query(
        `UPDATE employees 
         SET balance_al_carry_over = 0, updated_at = NOW()
         WHERE balance_al_carry_over > 0 AND is_inactive = false
         RETURNING email, name, balance_al_carry_over`
      );
      
      if (expireResult.rows.length > 0) {
        console.log(`❌ Expired carry over for ${expireResult.rows.length} employees`);
        
        // Create summary audit log
        const expiredList = expireResult.rows.map(emp => 
          `${emp.name} (${emp.email}): ${emp.balance_al_carry_over}d`
        ).join('; ');
        
        await audit(
          'system',
          'CARRY_OVER_EXPIRED',
          `Auto-expired carry over for ${expireResult.rows.length} employees past deadline ${deadlineMonth}/${deadlineDay}. Details: ${expiredList}`,
          null
        );
      }
    }
    
  } catch (e) {
    console.error('Carry over expiration check error:', e);
  }
}

// ===== SCHEDULED: Sync Daily Pro-Rated AL Accrual =====
async function syncProRatedALBalances() {
  try {
    const today = toDateOnly(new Date());
    if (!today) return;

    const syncDateStr = formatDateOnlyYYYYMMDD(today);
    const alreadySynced = await pool.query(
      `SELECT 1
       FROM audit_logs
       WHERE action = 'AL_PRORATA_SYNC'
         AND created_at >= CURRENT_DATE
       LIMIT 1`
    );
    if (alreadySynced.rows.length > 0) return;

    const employeesRes = await pool.query(
      `SELECT email, name, hire_date, annual_leave_base
       FROM employees
       WHERE is_inactive = false`
    );

    let processedCount = 0;
    for (const emp of employeesRes.rows) {
      const annualBase = Number(emp.annual_leave_base) || 0;
      const delta = getProRatedALDeltaForDate(annualBase, emp.hire_date, today);
      if (delta <= 0) continue;

      await pool.query(
        `UPDATE employees
         SET balance_al = ROUND((COALESCE(balance_al, 0) + $1)::numeric, 2),
             updated_at = NOW()
         WHERE email = $2`,
        [delta, emp.email]
      );
      processedCount++;
    }

    await audit(
      'system',
      'AL_PRORATA_SYNC',
      `Daily pro-rated AL sync completed for ${syncDateStr}. Updated ${processedCount} employees.`,
      null
    );
  } catch (e) {
    console.error('Daily pro-rated AL sync error:', e);
  }
}

// ===== SCHEDULED: Reset selected leave balances on Jan 1 =====
async function checkAndRunJan1LeaveTypeResets() {
  try {
    const now = new Date();
    const currentMonth = now.getMonth() + 1;
    const currentDay = now.getDate();
    if (currentMonth !== 1 || currentDay !== 1) return;

    const alreadyReset = await pool.query(
      `SELECT 1
       FROM audit_logs
       WHERE action IN ('JAN1_LEAVE_TYPE_RESET', 'BIRTHDAY_LEAVE_RESET')
         AND created_at >= CURRENT_DATE
       LIMIT 1`
    );
    if (alreadyReset.rows.length > 0) return;

    const settingKeys = Object.keys(JAN1_RESET_SETTING_DEFAULTS);
    const settingsRes = await pool.query(
      `SELECT setting_key, setting_value
       FROM system_settings
       WHERE setting_key = ANY($1::text[])`,
      [settingKeys]
    );
    const settingMap = {};
    settingsRes.rows.forEach((row) => {
      settingMap[row.setting_key] = normalizeBooleanSettingValue(
        row.setting_value,
        JAN1_RESET_SETTING_DEFAULTS[row.setting_key] || 'false'
      );
    });

    const resetConfigs = [
      { code: 'BL', settingKey: 'jan1_reset_bl_enabled', column: 'balance_bl', resetValue: 1 },
      { code: 'CL', settingKey: 'jan1_reset_cl_enabled', column: 'balance_cl', resetValue: 0 },
      { code: 'CPL', settingKey: 'jan1_reset_cpl_enabled', column: 'balance_cpl', resetValue: 0 },
      { code: 'DC', settingKey: 'jan1_reset_dc_enabled', column: 'balance_dc', resetValue: 0 },
      { code: 'ML', settingKey: 'jan1_reset_ml_enabled', column: 'balance_ml', resetValue: 0 },
      { code: 'PL', settingKey: 'jan1_reset_pl_enabled', column: 'balance_pl', resetValue: 0 },
      { code: 'SL', settingKey: 'jan1_reset_sl_enabled', column: 'balance_sl', resetValue: 0 }
    ];

    const details = [];
    let processedTypes = 0;
    for (const cfg of resetConfigs) {
      const enabled = (settingMap[cfg.settingKey] || JAN1_RESET_SETTING_DEFAULTS[cfg.settingKey]) === 'true';
      if (!enabled) continue;
      const resetRes = await pool.query(
        `UPDATE employees
         SET ${cfg.column} = $1, updated_at = NOW()
         WHERE is_inactive = false
           AND COALESCE(${cfg.column}, 0) <> $1`,
        [cfg.resetValue]
      );
      details.push(`${cfg.code} -> ${cfg.resetValue} (${resetRes.rowCount || 0} employee(s))`);
      processedTypes++;
    }

    if (processedTypes === 0) {
      await audit(
        'system',
        'JAN1_LEAVE_TYPE_RESET',
        'Jan-1 leave reset check ran: no leave type reset was enabled.',
        null
      );
      return;
    }

    await audit(
      'system',
      'JAN1_LEAVE_TYPE_RESET',
      `Jan-1 leave reset completed. ${details.join('; ')}`,
      null
    );
  } catch (e) {
    console.error('Jan-1 leave reset error:', e);
  }
}

async function purgeExpiredAttachments() {
  try {
    const alreadyPurgedToday = await pool.query(
      `SELECT 1
       FROM audit_logs
       WHERE action = 'ATTACHMENT_PURGE_7Y'
         AND created_at >= CURRENT_DATE
       LIMIT 1`
    );
    if (alreadyPurgedToday.rows.length > 0) return;

    const candidates = await pool.query(
      `SELECT id, documents
       FROM leave_requests
       WHERE documents IS NOT NULL
         AND jsonb_typeof(documents) = 'array'
         AND jsonb_array_length(documents) > 0
         AND COALESCE(end_date, start_date, DATE(submitted_at), DATE(created_at)) <= (CURRENT_DATE - INTERVAL '7 years')`
    );

    let requestsProcessed = 0;
    let filesDeleted = 0;

    for (const row of candidates.rows) {
      const docs = Array.isArray(row.documents) ? row.documents : [];
      let deletedForRequest = 0;

      for (const doc of docs) {
        const storedNameRaw = String((doc && doc.storedName) || '');
        const safeStoredName = path.basename(storedNameRaw);
        if (!safeStoredName || safeStoredName !== storedNameRaw) continue;

        const filePath = path.join(UPLOAD_DIR, safeStoredName);
        const resolvedPath = path.resolve(filePath);
        const resolvedUploadDir = path.resolve(UPLOAD_DIR);
        if (!resolvedPath.startsWith(resolvedUploadDir + path.sep)) continue;

        if (fs.existsSync(resolvedPath)) {
          try {
            fs.unlinkSync(resolvedPath);
            deletedForRequest++;
          } catch (_) {}
        }
      }

      await pool.query(
        `UPDATE leave_requests
         SET documents = '[]'::jsonb, updated_at = NOW()
         WHERE id = $1`,
        [row.id]
      );

      requestsProcessed++;
      filesDeleted += deletedForRequest;
    }

    await audit(
      'system',
      'ATTACHMENT_PURGE_7Y',
      `Attachment purge completed. Requests processed: ${requestsProcessed}, Files deleted: ${filesDeleted}.`,
      null
    );
  } catch (e) {
    console.error('Attachment purge error:', e);
  }
}


// Run both scheduled checks every hour
setInterval(() => {
  syncProRatedALBalances();
  checkAndRunJan1LeaveTypeResets();
  checkAndExpireCarryOver();
  checkAndRunYearEndRollover();
  purgeExpiredAttachments();
}, 3600000); // Every 1 hour

// Also run on server start
syncProRatedALBalances();
checkAndRunJan1LeaveTypeResets();
checkAndExpireCarryOver();
checkAndRunYearEndRollover();
purgeExpiredAttachments();


// ===== TRIGGER MANUAL YEAR-END ROLLOVER =====
app.post('/api/admin/trigger-rollover', auth, requireAdmin, async (req, res) => {
  try {
    console.log('Manual rollover triggered by:', req.user.email);
    
    // Get system settings
    const settingsRes = await pool.query(
      `SELECT setting_key, setting_value FROM system_settings 
       WHERE setting_key IN ('al_carry_over_enabled', 'al_carry_over_max_days')`
    );
    
    const settings = {};
    settingsRes.rows.forEach(row => {
      settings[row.setting_key] = row.setting_value;
    });
    
    const carryOverEnabled = settings.al_carry_over_enabled === 'true';
    const maxCarryOverDays = parseInt(settings.al_carry_over_max_days || 99);
    
    if (!carryOverEnabled) {
      return res.status(400).json({ error: 'Carry over is disabled in system settings' });
    }
    
    // Get all active employees
    const employeesRes = await pool.query(
      `SELECT email, name, balance_al, annual_leave_base, balance_al_carry_over, hire_date
       FROM employees 
       WHERE is_inactive = false`
    );
    
    let processedCount = 0;
    let rolloverDetails = [];
    
    for (const emp of employeesRes.rows) {
      const currentAL = parseFloat(emp.balance_al) || 0;
      const currentCarryOver = parseFloat(emp.balance_al_carry_over) || 0;
      const annualBase = emp.annual_leave_base === null || emp.annual_leave_base === undefined
        ? 14
        : Number(emp.annual_leave_base);
      
      // Calculate transfer amount from last year's unused AL
      let toCarryOver = currentAL; // All unused AL
      
      // Cap applies only to this annual transfer amount
      if (toCarryOver > maxCarryOverDays) {
        toCarryOver = maxCarryOverDays;
      }
      
      // New balances:
      // - Existing carry over remains available regardless of age
      // - Unused AL becomes additional carry over
      // - AL balance resets to current pro-rated entitlement
      const newCarryOver = round2(currentCarryOver + toCarryOver);
      const newAL = getProRatedALAsOfDate(annualBase, emp.hire_date, new Date());
      const forfeitedExcessAL = currentAL - toCarryOver;
      
      // Update employee
      await pool.query(
        `UPDATE employees 
         SET balance_al = $1, 
             balance_al_carry_over = $2, 
             updated_at = NOW()
         WHERE email = $3`,
        [newAL, newCarryOver, emp.email]
      );
      
      // Build detailed log message
      let logMsg = `${emp.name} (${emp.email}): `;
      logMsg += `AL ${currentAL}d → ${newAL}d (completed-day pro-rata), `;
      logMsg += `Carry Over ${currentCarryOver}d → ${newCarryOver}d`;

      if (forfeitedExcessAL > 0) {
        logMsg += ` [Forfeited excess AL: ${forfeitedExcessAL}d]`;
      }
      
      rolloverDetails.push(logMsg);
      processedCount++;
    }
    
    // Create audit log entry
    const summaryDetails = `Year-end rollover completed (completed-day pro-rata). Processed ${processedCount} employees. ` +
      `Transfer cap from last-year AL: ${maxCarryOverDays} days (existing carry over preserved). Details: ${rolloverDetails.join('; ')}`;
    
    await audit(req.user.email, 'YEAR_END_ROLLOVER', summaryDetails, req);
    
    res.json({
      success: true,
      processed: processedCount,
      message: `Year-end rollover completed for ${processedCount} employees`
    });
    
  } catch (e) {
    console.error('Rollover error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ===== GET ROLLOVER HISTORY =====
app.get('/api/admin/rollover-history', auth, requireAdmin, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 20;
    
    const result = await pool.query(
      `SELECT user_email, action, details, created_at 
       FROM audit_logs 
       WHERE action IN ('YEAR_END_ROLLOVER', 'CARRY_OVER_EXPIRED')
       ORDER BY created_at DESC 
       LIMIT $1`,
      [limit]
    );
    
    res.json(result.rows);
    
  } catch (e) {
    console.error('Get rollover history error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ===== AUTOMATIC YEAR-END ROLLOVER (Scheduled) =====
async function checkAndRunYearEndRollover() {
  try {
    const now = new Date();
    const currentMonth = now.getMonth() + 1; // 1-12
    const currentDay = now.getDate();
    const currentHour = now.getHours();
    
    // Run on January 1st at 3 AM HKT
    if (currentMonth === 1 && currentDay === 1 && currentHour === 3) {
      console.log('🔄 Running automatic year-end rollover...');
      
      // Check if already ran today
      const lastRolloverCheck = await pool.query(
        `SELECT created_at FROM audit_logs 
         WHERE action = 'YEAR_END_ROLLOVER' 
         AND created_at >= CURRENT_DATE 
         LIMIT 1`
      );
      
      if (lastRolloverCheck.rows.length > 0) {
        console.log('⏭️ Rollover already ran today, skipping');
        return;
      }
      
      // Get settings
      const settingsRes = await pool.query(
        `SELECT setting_key, setting_value FROM system_settings 
         WHERE setting_key IN ('al_carry_over_enabled', 'al_carry_over_max_days')`
      );
      
      const settings = {};
      settingsRes.rows.forEach(row => {
        settings[row.setting_key] = row.setting_value;
      });
      
      const carryOverEnabled = settings.al_carry_over_enabled === 'true';
      const maxCarryOverDays = parseInt(settings.al_carry_over_max_days || 99);
      
      if (!carryOverEnabled) {
        console.log('⚠️ Carry over disabled, skipping rollover');
        return;
      }
      
      // Get all active employees
      const employeesRes = await pool.query(
      `SELECT email, name, balance_al, annual_leave_base, balance_al_carry_over, hire_date
         FROM employees 
         WHERE is_inactive = false`
      );
      
      let processedCount = 0;
      
      for (const emp of employeesRes.rows) {
        const currentAL = parseFloat(emp.balance_al) || 0;
        const currentCarryOver = parseFloat(emp.balance_al_carry_over) || 0;
        const annualBase = emp.annual_leave_base === null || emp.annual_leave_base === undefined
          ? 14
          : Number(emp.annual_leave_base);
        
        let toCarryOver = Math.min(currentAL, maxCarryOverDays);
        const newCarryOver = round2(currentCarryOver + toCarryOver);
        const newAL = getProRatedALAsOfDate(annualBase, emp.hire_date, now);
        
        await pool.query(
          `UPDATE employees 
           SET balance_al = $1, balance_al_carry_over = $2, updated_at = NOW()
           WHERE email = $3`,
          [newAL, newCarryOver, emp.email]
        );
        
        processedCount++;
      }
      
      await audit(
        'system',
        'YEAR_END_ROLLOVER',
        `Automatic year-end rollover completed (completed-day pro-rata). Processed ${processedCount} employees. Transfer cap from last-year AL: ${maxCarryOverDays} days (existing carry over preserved).`,
        null
      );
      
      console.log(`✅ Rollover completed: ${processedCount} employees processed`);
    }
    
  } catch (e) {
    console.error('Automatic rollover error:', e);
  }
}

// ===== GET ALL LEAVE REQUESTS (Admin Only) =====
app.get('/api/admin/all-leave-requests', auth, requireAdmin, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    
    const result = await pool.query(
      `SELECT lr.*, e.name as employee_name
       FROM leave_requests lr
       JOIN employees e ON lr.employee_email = e.email
       ORDER BY lr.submitted_at DESC
       LIMIT $1`,
      [limit]
    );
    
    res.json(result.rows);
    
  } catch (e) {
    console.error('Get all leave requests error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/admin/approval-history-monthly', auth, requireAdmin, async (req, res) => {
  try {
    const month = String(req.query.month || '').trim();
    const limit = Math.min(parseInt(req.query.limit || '500', 10), 1000);
    const monthPattern = /^\d{4}-\d{2}$/;

    const now = new Date();
    const currentMonth = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
    const targetMonth = monthPattern.test(month) ? month : currentMonth;

    const result = await pool.query(
      `SELECT
         lr.id,
         lr.employee_email,
         e.name AS employee_name,
         lr.type,
         lr.start_date,
         lr.end_date,
         lr.days,
         lr.status,
         lr.submitted_at,
         lr.approved_by,
         lr.approved_at,
         lr.manager_notes
       FROM leave_requests lr
       JOIN employees e ON lr.employee_email = e.email
       WHERE lr.status IN ('approved', 'rejected')
         AND TO_CHAR(COALESCE(lr.approved_at, lr.submitted_at), 'YYYY-MM') = $1
       ORDER BY COALESCE(lr.approved_at, lr.submitted_at) DESC
       LIMIT $2`,
      [targetMonth, limit]
    );

    res.json({ month: targetMonth, records: result.rows });
  } catch (e) {
    console.error('Get monthly approval history error:', e);
    res.status(500).json({ error: e.message });
  }
});


const PORT = Number(process.env.PORT || 3000);

async function startServer() {
  try {
    await ensureRuntimeSchema();
    app.listen(PORT, () => {
      console.log(`\n========================================`);
      console.log(`Case Study Leave Management System v1.0`);
      console.log(`API running on port ${PORT}`);
      console.log(`Timezone: ${APP_TIMEZONE} (UTC+8)`);
      console.log(`========================================\n`);
    });
  } catch (e) {
    console.error('Failed to initialize runtime schema:', e);
    process.exit(1);
  }
}

startServer();

