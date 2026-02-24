-- ============================================
-- CASE STUDY LEAVE MANAGEMENT SYSTEM v1.0
-- ============================================

-- Base tables
CREATE TABLE IF NOT EXISTS employees (
    email VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    department VARCHAR(100),
    role VARCHAR(20) NOT NULL DEFAULT 'employee',
    manager_email VARCHAR(255) REFERENCES employees(email),
    hire_date DATE NOT NULL,
    annual_leave_base INT NOT NULL DEFAULT 12,
    carry_over_reset_month INT NOT NULL DEFAULT 10,
    
    -- Leave balances
    balance_al DECIMAL(5,2) NOT NULL DEFAULT 0,
    balance_al_carry_over DECIMAL(5,2) NOT NULL DEFAULT 0,
    balance_bl DECIMAL(5,2) NOT NULL DEFAULT 1,
    balance_cl DECIMAL(5,2) NOT NULL DEFAULT 0,
    balance_cpl DECIMAL(5,2) NOT NULL DEFAULT 0,
    balance_dc DECIMAL(5,2) NOT NULL DEFAULT 0,
    balance_ml DECIMAL(5,2) NOT NULL DEFAULT 0,
    balance_pl DECIMAL(5,2) NOT NULL DEFAULT 0,
    balance_sl DECIMAL(5,2) NOT NULL DEFAULT 0,
    
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    location VARCHAR(100) NOT NULL DEFAULT 'Sample Region',
    staff_code VARCHAR(20) UNIQUE,
    is_inactive BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT chk_role CHECK (role IN ('employee', 'approver', 'admin')),
    CONSTRAINT chk_employee_status CHECK (status IN ('active', 'inactive')),
    CONSTRAINT chk_manager_not_self CHECK (manager_email IS NULL OR manager_email <> email),
    CONSTRAINT chk_annual_leave_base_non_negative CHECK (annual_leave_base >= 0),
    CONSTRAINT chk_carry_over_reset_month CHECK (carry_over_reset_month BETWEEN 1 AND 12),
    CONSTRAINT chk_balance_al_carry_over_non_negative CHECK (balance_al_carry_over >= 0)
);

CREATE TABLE IF NOT EXISTS leave_requests (
    id VARCHAR(50) PRIMARY KEY,
    employee_email VARCHAR(255) NOT NULL REFERENCES employees(email) ON DELETE RESTRICT,
    type VARCHAR(10) NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    start_duration_type VARCHAR(10) NOT NULL DEFAULT 'FULL',
    end_duration_type VARCHAR(10) NOT NULL DEFAULT 'FULL',
    days DECIMAL(5,1) NOT NULL,
    remarks TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    documents JSONB,
    submitted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    manager_notes TEXT,
    approved_by VARCHAR(255) REFERENCES employees(email) ON DELETE SET NULL,
    approved_at TIMESTAMP,
    hr_reviewed BOOLEAN NOT NULL DEFAULT false,
    hr_reviewed_by VARCHAR(255) REFERENCES employees(email) ON DELETE SET NULL,
    hr_reviewed_at TIMESTAMP,
    supervisor_notified BOOLEAN NOT NULL DEFAULT false,
    supervisor_notified_at TIMESTAMP,
    retail_workflow BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_leave_request_type CHECK (type IN ('AL', 'BL', 'CL', 'CPL', 'DC', 'ML', 'PL', 'SL', 'OTHER')),
    CONSTRAINT chk_leave_request_status CHECK (status IN ('pending', 'approved', 'rejected')),
    CONSTRAINT chk_leave_request_duration_types CHECK (
      start_duration_type IN ('FULL', 'AM', 'PM')
      AND end_duration_type IN ('FULL', 'AM', 'PM')
    ),
    CONSTRAINT chk_leave_request_days_positive CHECK (days > 0),
    CONSTRAINT chk_leave_request_date_order CHECK (end_date >= start_date),
    CONSTRAINT chk_leave_request_approval_state CHECK (
      (status = 'pending' AND approved_by IS NULL AND approved_at IS NULL)
      OR
      (status IN ('approved', 'rejected') AND approved_by IS NOT NULL AND approved_at IS NOT NULL)
    ),
    CONSTRAINT chk_leave_request_hr_review_state CHECK (
      (hr_reviewed = false AND hr_reviewed_by IS NULL AND hr_reviewed_at IS NULL)
      OR
      (hr_reviewed = true AND hr_reviewed_by IS NOT NULL AND hr_reviewed_at IS NOT NULL)
    ),
    CONSTRAINT chk_leave_request_supervisor_notify_state CHECK (
      supervisor_notified = false OR supervisor_notified_at IS NOT NULL
    )
);

-- Counter table to guarantee non-reused request IDs per staff code and date
CREATE TABLE IF NOT EXISTS leave_request_id_counters (
    staff_code VARCHAR(20) NOT NULL,
    request_date DATE NOT NULL,
    last_sequence INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (staff_code, request_date),
    CONSTRAINT chk_leave_request_id_counter_non_negative CHECK (last_sequence >= 0)
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id SERIAL PRIMARY KEY,
  user_email VARCHAR(255) REFERENCES employees(email) ON DELETE SET NULL,
  action VARCHAR(255) NOT NULL,
  details TEXT,
  ip_address VARCHAR(45),
  user_agent TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE IF NOT EXISTS holidays (
    date DATE PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS calendar_day_remarks (
    date DATE PRIMARY KEY,
    remark TEXT NOT NULL,
    created_by VARCHAR(255) REFERENCES employees(email) ON DELETE SET NULL,
    updated_by VARCHAR(255) REFERENCES employees(email) ON DELETE SET NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS staff_settings (
    id SERIAL PRIMARY KEY,
    employee_email VARCHAR(255) NOT NULL UNIQUE REFERENCES employees(email) ON DELETE CASCADE,
    location VARCHAR(100),
    supervisor_email VARCHAR(255) REFERENCES employees(email) ON DELETE SET NULL,
    is_office_staff BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS smtp_config (
    id SERIAL PRIMARY KEY,
    host VARCHAR(255) NOT NULL,
    port INT NOT NULL,
    use_auth BOOLEAN DEFAULT false,
    username VARCHAR(255),
    password VARCHAR(255),
    from_email VARCHAR(255) NOT NULL,
    shared_mailbox VARCHAR(255) NOT NULL,
    is_enabled BOOLEAN DEFAULT false,
    created_by VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_smtp_port CHECK (port BETWEEN 1 AND 65535)
);

CREATE TABLE IF NOT EXISTS email_logs (
    id SERIAL PRIMARY KEY,
    to_email VARCHAR(255),
    subject VARCHAR(255),
    email_type VARCHAR(50) NOT NULL,
    leave_request_id VARCHAR(50) REFERENCES leave_requests(id) ON DELETE SET NULL,
    status VARCHAR(20) NOT NULL,
    error_message TEXT,
    sent_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_email_logs_status CHECK (status IN ('sent', 'failed', 'skipped_no_smtp'))
);

CREATE TABLE IF NOT EXISTS reports (
    id SERIAL PRIMARY KEY,
    report_type VARCHAR(50),
    title VARCHAR(255),
    description TEXT,
    created_by VARCHAR(255),
    filters JSONB,
    export_format VARCHAR(20),
    file_url VARCHAR(500),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

-- Add global AL carry over settings table
CREATE TABLE IF NOT EXISTS system_settings (
  id SERIAL PRIMARY KEY,
  setting_key VARCHAR(100) UNIQUE NOT NULL,
  setting_value TEXT,
  description TEXT,
  updated_by VARCHAR(255),
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Generic trigger to maintain updated_at for mutable tables
CREATE OR REPLACE FUNCTION set_updated_at_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_employees_set_updated_at') THEN
    CREATE TRIGGER trg_employees_set_updated_at
      BEFORE UPDATE ON employees
      FOR EACH ROW
      EXECUTE FUNCTION set_updated_at_timestamp();
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_leave_requests_set_updated_at') THEN
    CREATE TRIGGER trg_leave_requests_set_updated_at
      BEFORE UPDATE ON leave_requests
      FOR EACH ROW
      EXECUTE FUNCTION set_updated_at_timestamp();
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_leave_request_id_counters_set_updated_at') THEN
    CREATE TRIGGER trg_leave_request_id_counters_set_updated_at
      BEFORE UPDATE ON leave_request_id_counters
      FOR EACH ROW
      EXECUTE FUNCTION set_updated_at_timestamp();
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_calendar_day_remarks_set_updated_at') THEN
    CREATE TRIGGER trg_calendar_day_remarks_set_updated_at
      BEFORE UPDATE ON calendar_day_remarks
      FOR EACH ROW
      EXECUTE FUNCTION set_updated_at_timestamp();
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_staff_settings_set_updated_at') THEN
    CREATE TRIGGER trg_staff_settings_set_updated_at
      BEFORE UPDATE ON staff_settings
      FOR EACH ROW
      EXECUTE FUNCTION set_updated_at_timestamp();
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_smtp_config_set_updated_at') THEN
    CREATE TRIGGER trg_smtp_config_set_updated_at
      BEFORE UPDATE ON smtp_config
      FOR EACH ROW
      EXECUTE FUNCTION set_updated_at_timestamp();
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_system_settings_set_updated_at') THEN
    CREATE TRIGGER trg_system_settings_set_updated_at
      BEFORE UPDATE ON system_settings
      FOR EACH ROW
      EXECUTE FUNCTION set_updated_at_timestamp();
  END IF;
END $$;

-- Indexes
CREATE INDEX IF NOT EXISTS idx_employee_role ON employees(role);
CREATE INDEX IF NOT EXISTS idx_employee_manager ON employees(manager_email);
CREATE INDEX IF NOT EXISTS idx_employee_location ON employees(location);
CREATE INDEX IF NOT EXISTS idx_employee_inactive ON employees(is_inactive);
CREATE INDEX IF NOT EXISTS idx_employee_email_lower ON employees(LOWER(email));
CREATE INDEX IF NOT EXISTS idx_employee_staff_code_upper ON employees(UPPER(staff_code));
CREATE INDEX IF NOT EXISTS idx_leave_request_employee ON leave_requests(employee_email);
CREATE INDEX IF NOT EXISTS idx_leave_request_status ON leave_requests(status);
CREATE INDEX IF NOT EXISTS idx_leave_request_dates ON leave_requests(start_date, end_date);
CREATE INDEX IF NOT EXISTS idx_leave_request_hr_reviewed ON leave_requests(hr_reviewed);
CREATE INDEX IF NOT EXISTS idx_leave_request_approved_by ON leave_requests(approved_by);
CREATE INDEX IF NOT EXISTS idx_leave_request_hr_reviewed_by ON leave_requests(hr_reviewed_by);
CREATE INDEX IF NOT EXISTS idx_leave_request_id_counters_date ON leave_request_id_counters(request_date);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_email);
CREATE INDEX IF NOT EXISTS idx_audit_date ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_ip ON audit_logs(ip_address);
CREATE INDEX IF NOT EXISTS idx_holidays_date ON holidays(date);
CREATE INDEX IF NOT EXISTS idx_calendar_day_remarks_date ON calendar_day_remarks(date);
CREATE INDEX IF NOT EXISTS idx_calendar_day_remarks_created_by ON calendar_day_remarks(created_by);
CREATE INDEX IF NOT EXISTS idx_calendar_day_remarks_updated_by ON calendar_day_remarks(updated_by);
CREATE INDEX IF NOT EXISTS idx_staff_settings_location ON staff_settings(location);
CREATE INDEX IF NOT EXISTS idx_staff_settings_supervisor ON staff_settings(supervisor_email);
CREATE INDEX IF NOT EXISTS idx_staff_settings_employee ON staff_settings(employee_email);
CREATE INDEX IF NOT EXISTS idx_email_logs_status ON email_logs(status);
CREATE INDEX IF NOT EXISTS idx_email_logs_type ON email_logs(email_type);
CREATE INDEX IF NOT EXISTS idx_email_logs_leave_request ON email_logs(leave_request_id);
CREATE INDEX IF NOT EXISTS idx_reports_type ON reports(report_type);
CREATE INDEX IF NOT EXISTS idx_system_settings_key ON system_settings(setting_key);

-- ========================================
-- TEST DATA
-- ========================================
-- Password policy: default password = staff_code + 'lms'

INSERT INTO employees (
  email, name, password_hash, department, manager_email, location, staff_code, role,
  hire_date, annual_leave_base, balance_al, balance_al_carry_over, balance_bl, balance_cl, balance_sl
) VALUES
-- Admin account
('leave@example.com', 'System Admin', '$2a$10$56qiQ8RFhvj8lSu1ZdaHDOien2ujNh.P7366YdK3QhbqPIAFhNSiO', 'HR', NULL, 'Sample Region', 'ADMIN', 'admin', '2021-03-15', 0, 0, 2.5, 0, 0, 0),

-- Superadmin account (mapped by email in API login)
('it@example.com', 'Platform Owner', '$2a$10$PaKKOm1C9mwBhVHNNUbwguyJZuron/W96KtaIJRTUV8EMXinBAEWi', 'IT', NULL, 'Sample Region', 'IT001', 'admin', '2020-11-02', 0, 0, 1.0, 0, 0, 0),

-- Approvers
('john@example.com', 'Alex Manager', '$2a$10$FBfs3ZRnWhl5tf/9Ms22HuT3wDjbueTFQeeOtA/.aa6vfprO/.z.a', 'Sales', NULL, 'Sample Region', 'MG001', 'approver', '2022-09-19', 12, 0.0, 3.5, 1.0, 0, 0),

-- Office Staff
('mary@example.com', 'Taylor Employee', '$2a$10$nmXS9vWEOTZqUj9xP7eYVemYYce1Alv4j/2d.JliJkqIQr3XJv0vm', 'Sales', 'john@example.com', 'Sample Region', 'OF001', 'employee', '2023-05-08', 12, 0.0, 0.8, 1.0, 0, 0),

-- Retail Staff
('peter@example.com', 'Retail Staff', '$2a$10$65fF3sLxSLGG/62M..y9/uGtWQLRVkVwV8zQF9l6yjM6LMRBEiGAS', 'Retail', 'supervisor@example.com', 'Retail Store 1', 'RT001', 'employee', '2024-01-22', 12, 0.0, 2.0, 1.0, 0, 0),

-- Retail Staff
('supervisor@example.com', 'Retail Lead', '$2a$10$Wxk.8rJTXkddWvYEUjfdIOs.62HfGSLUAMZYCdJkrlRzsxw.njGqC', 'Retail', 'leave@example.com', 'Retail', 'DJ001', 'approver', '2021-07-05', 12, 0.0, 4.2, 1.0, 0, 0);

-- Staff settings
INSERT INTO staff_settings (employee_email, location, supervisor_email, is_office_staff)
VALUES
('mary@example.com', 'Office', 'john@example.com', true),
('john@example.com', 'Office', 'leave@example.com', true),
('it@example.com', 'Office', 'leave@example.com', true),
('peter@example.com', 'Retail', 'supervisor@example.com', false),
('supervisor@example.com', 'Retail', 'leave@example.com', false);

-- Default SMTP config
INSERT INTO smtp_config (host, port, use_auth, from_email, shared_mailbox, is_enabled, created_by)
VALUES ('example.com.mail.protection.outlook.com', 25, false, 'leave@example.com', 'leave@example.com', true, 'system');

-- Insert default AL carry over settings
INSERT INTO system_settings (setting_key, setting_value, description, updated_by) 
VALUES 
  ('al_carry_over_enabled', 'true', 'Enable annual leave carry over', 'system'),
  ('al_carry_over_max_days', '99', 'Maximum days allowed to carry over', 'system'),
  ('al_carry_over_forfeit_enabled', 'false', 'Whether to hard-forfeit carry over balance after deadline', 'system'),
  ('al_carry_over_deadline_month', '10', 'Month when carry over expires (1-12)', 'system'),
  ('al_carry_over_deadline_day', '31', 'Day of month when carry over expires', 'system'),
  ('approved_leave_admin_delete_window_days', '14', 'Admin approved-leave cancellation window in days after approval (0 = unlimited)', 'system'),
  ('jan1_reset_bl_enabled', 'true', 'Enable Jan-1 reset for BL (to 1)', 'system'),
  ('jan1_reset_cl_enabled', 'false', 'Enable Jan-1 reset for CL (to 0)', 'system'),
  ('jan1_reset_cpl_enabled', 'false', 'Enable Jan-1 reset for CPL (to 0)', 'system'),
  ('jan1_reset_dc_enabled', 'false', 'Enable Jan-1 reset for DC (to 0)', 'system'),
  ('jan1_reset_ml_enabled', 'false', 'Enable Jan-1 reset for ML (to 0)', 'system'),
  ('jan1_reset_pl_enabled', 'false', 'Enable Jan-1 reset for PL (to 0)', 'system'),
  ('jan1_reset_sl_enabled', 'false', 'Enable Jan-1 reset for SL (to 0)', 'system')
ON CONFLICT (setting_key) DO NOTHING;

-- Add carry_over_reset_month to employees if not exists
ALTER TABLE employees 
ADD COLUMN IF NOT EXISTS carry_over_reset_month INT DEFAULT 10;

-- Add comment
COMMENT ON COLUMN employees.carry_over_reset_month IS 'Month (1-12) when carry over AL expires. Default 10 = October 31';

-- Ensure balance AL default follows pro-rata sync logic (not fixed annual grant)
ALTER TABLE employees
ALTER COLUMN balance_al SET DEFAULT 0;

-- Ensure annual leave base default is 12 for new employee records
ALTER TABLE employees
ALTER COLUMN annual_leave_base SET DEFAULT 12;

-- Sample Region public holidays 2026
INSERT INTO holidays (date, name) VALUES
-- Q1 2026
('2026-01-01', 'New Year''s Day'),
('2026-02-17', 'Lunar New Year''s Day'),
('2026-02-18', 'Second Day of Lunar New Year'),
('2026-02-19', 'Third Day of Lunar New Year'),
-- Q2 2026
('2026-04-03', 'Good Friday'),
('2026-04-04', 'Day following Good Friday'),
('2026-04-06', 'Day following Ching Ming Festival'),
('2026-04-07', 'Day following Easter Monday'),
('2026-05-01', 'Labour Day'),
('2026-05-25', 'Day following Buddha''s Birthday'),
('2026-06-19', 'Tuen Ng Festival'),
-- Q3 2026
('2026-07-01', 'HKSAR Establishment Day'),
('2026-09-26', 'Day after Mid-Autumn Festival'),
-- Q4 2026
('2026-10-01', 'National Day'),
('2026-10-19', 'Day following Chung Yeung Festival'),
('2026-12-25', 'Christmas Day'),
('2026-12-26', 'First Weekday After Christmas Day');
