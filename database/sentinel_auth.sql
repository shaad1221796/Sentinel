-- ============================================================
--  SENTINEL IDS — Complete Auth Database Schema
--  Compatible with: MySQL 8.0+ / MariaDB 10.6+
--
--  HOW TO RUN:
--  MySQL Workbench → File → Open SQL Script → select this file
--                 → click the ⚡ lightning bolt button
-- ============================================================

-- ── DATABASE SETUP ──────────────────────────────────────────
CREATE DATABASE IF NOT EXISTS sentinel_auth
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE sentinel_auth;

-- ============================================================
--  TABLE 1: users
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id                  INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    uuid                CHAR(36)        NOT NULL UNIQUE DEFAULT (UUID()),
    first_name          VARCHAR(60)     NOT NULL,
    last_name           VARCHAR(60)     NOT NULL,
    email               VARCHAR(255)    NOT NULL UNIQUE,
    password_hash       VARCHAR(255)    NOT NULL,
    organisation        VARCHAR(120)    NULL,
    role                ENUM('admin','analyst','viewer') NOT NULL DEFAULT 'viewer',
    is_active           TINYINT(1)      NOT NULL DEFAULT 1,
    is_email_verified   TINYINT(1)      NOT NULL DEFAULT 0,
    avatar_url          VARCHAR(500)    NULL,
    created_at          DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP
                          ON UPDATE CURRENT_TIMESTAMP,
    deleted_at          DATETIME        NULL,

    PRIMARY KEY (id),
    INDEX idx_users_email       (email),
    INDEX idx_users_uuid        (uuid),
    INDEX idx_users_role        (role),
    INDEX idx_users_is_active   (is_active),
    INDEX idx_users_created_at  (created_at)
) ENGINE=InnoDB;


-- ============================================================
--  TABLE 2: email_verifications
-- ============================================================
CREATE TABLE IF NOT EXISTS email_verifications (
    id          INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    user_id     INT UNSIGNED    NOT NULL,
    token       VARCHAR(128)    NOT NULL UNIQUE,
    expires_at  DATETIME        NOT NULL,
    used_at     DATETIME        NULL,
    created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    INDEX idx_ev_user_id  (user_id),
    INDEX idx_ev_token    (token),
    INDEX idx_ev_expires  (expires_at),

    CONSTRAINT fk_ev_user
      FOREIGN KEY (user_id) REFERENCES users(id)
      ON DELETE CASCADE
) ENGINE=InnoDB;


-- ============================================================
--  TABLE 3: sessions
-- ============================================================
CREATE TABLE IF NOT EXISTS sessions (
    id              INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    user_id         INT UNSIGNED    NOT NULL,
    token_hash      VARCHAR(255)    NOT NULL UNIQUE,
    ip_address      VARCHAR(45)     NULL,
    user_agent      TEXT            NULL,
    device_name     VARCHAR(120)    NULL,
    is_active       TINYINT(1)      NOT NULL DEFAULT 1,
    last_active_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at      DATETIME        NOT NULL,
    created_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at      DATETIME        NULL,

    PRIMARY KEY (id),
    INDEX idx_sess_user_id    (user_id),
    INDEX idx_sess_token_hash (token_hash),
    INDEX idx_sess_is_active  (is_active),
    INDEX idx_sess_expires_at (expires_at),

    CONSTRAINT fk_sess_user
      FOREIGN KEY (user_id) REFERENCES users(id)
      ON DELETE CASCADE
) ENGINE=InnoDB;


-- ============================================================
--  TABLE 4: password_reset_tokens
-- ============================================================
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id          INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    user_id     INT UNSIGNED    NOT NULL,
    token       VARCHAR(128)    NOT NULL UNIQUE,
    expires_at  DATETIME        NOT NULL,
    used_at     DATETIME        NULL,
    ip_address  VARCHAR(45)     NULL,
    created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    INDEX idx_prt_user_id (user_id),
    INDEX idx_prt_token   (token),
    INDEX idx_prt_expires (expires_at),

    CONSTRAINT fk_prt_user
      FOREIGN KEY (user_id) REFERENCES users(id)
      ON DELETE CASCADE
) ENGINE=InnoDB;


-- ============================================================
--  TABLE 5: login_attempts
-- ============================================================
CREATE TABLE IF NOT EXISTS login_attempts (
    id              INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    email           VARCHAR(255)    NOT NULL,
    user_id         INT UNSIGNED    NULL,
    ip_address      VARCHAR(45)     NOT NULL,
    user_agent      TEXT            NULL,
    success         TINYINT(1)      NOT NULL DEFAULT 0,
    failure_reason  ENUM(
                      'invalid_password',
                      'user_not_found',
                      'account_locked',
                      'account_inactive',
                      'email_not_verified',
                      'too_many_attempts'
                    ) NULL,
    attempted_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    INDEX idx_la_email        (email),
    INDEX idx_la_ip           (ip_address),
    INDEX idx_la_user_id      (user_id),
    INDEX idx_la_success      (success),
    INDEX idx_la_attempted_at (attempted_at),

    CONSTRAINT fk_la_user
      FOREIGN KEY (user_id) REFERENCES users(id)
      ON DELETE SET NULL
) ENGINE=InnoDB;


-- ============================================================
--  TABLE 6: account_lockouts
-- ============================================================
CREATE TABLE IF NOT EXISTS account_lockouts (
    id              INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    user_id         INT UNSIGNED    NOT NULL,
    locked_at       DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    unlock_at       DATETIME        NOT NULL,
    reason          VARCHAR(255)    NULL,
    unlocked_early  TINYINT(1)      NOT NULL DEFAULT 0,
    unlocked_at     DATETIME        NULL,
    unlocked_by     INT UNSIGNED    NULL,

    PRIMARY KEY (id),
    INDEX idx_al_user_id   (user_id),
    INDEX idx_al_unlock_at (unlock_at),

    CONSTRAINT fk_al_user
      FOREIGN KEY (user_id) REFERENCES users(id)
      ON DELETE CASCADE,

    CONSTRAINT fk_al_unlocked_by
      FOREIGN KEY (unlocked_by) REFERENCES users(id)
      ON DELETE SET NULL
) ENGINE=InnoDB;


-- ============================================================
--  TABLE 7: oauth_providers
-- ============================================================
CREATE TABLE IF NOT EXISTS oauth_providers (
    id                  INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    user_id             INT UNSIGNED    NOT NULL,
    provider            ENUM('google','github','microsoft','linkedin') NOT NULL,
    provider_user_id    VARCHAR(255)    NOT NULL,
    provider_email      VARCHAR(255)    NULL,
    access_token        TEXT            NULL,
    refresh_token       TEXT            NULL,
    token_expires_at    DATETIME        NULL,
    created_at          DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP
                          ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE KEY uq_oauth_provider (provider, provider_user_id),
    INDEX idx_oauth_user_id (user_id),

    CONSTRAINT fk_oauth_user
      FOREIGN KEY (user_id) REFERENCES users(id)
      ON DELETE CASCADE
) ENGINE=InnoDB;


-- ============================================================
--  TABLE 8: user_audit_log
-- ============================================================
CREATE TABLE IF NOT EXISTS user_audit_log (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id     INT UNSIGNED    NULL,
    action      VARCHAR(80)     NOT NULL,
    description TEXT            NULL,
    ip_address  VARCHAR(45)     NULL,
    user_agent  TEXT            NULL,
    metadata    JSON            NULL,
    created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    INDEX idx_ual_user_id    (user_id),
    INDEX idx_ual_action     (action),
    INDEX idx_ual_created_at (created_at),

    CONSTRAINT fk_ual_user
      FOREIGN KEY (user_id) REFERENCES users(id)
      ON DELETE SET NULL
) ENGINE=InnoDB;


-- ============================================================
--  TABLE 9: user_preferences
-- ============================================================
CREATE TABLE IF NOT EXISTS user_preferences (
    user_id             INT UNSIGNED    NOT NULL,
    theme               ENUM('light','dark','system') NOT NULL DEFAULT 'system',
    language            VARCHAR(10)     NOT NULL DEFAULT 'en',
    timezone            VARCHAR(60)     NOT NULL DEFAULT 'UTC',
    notifications_email TINYINT(1)      NOT NULL DEFAULT 1,
    notifications_web   TINYINT(1)      NOT NULL DEFAULT 1,
    two_factor_enabled  TINYINT(1)      NOT NULL DEFAULT 0,
    updated_at          DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP
                          ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (user_id),

    CONSTRAINT fk_pref_user
      FOREIGN KEY (user_id) REFERENCES users(id)
      ON DELETE CASCADE
) ENGINE=InnoDB;


-- ============================================================
--  TABLE 10: two_factor_auth
-- ============================================================
CREATE TABLE IF NOT EXISTS two_factor_auth (
    id          INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    user_id     INT UNSIGNED    NOT NULL UNIQUE,
    method      ENUM('totp','email','sms') NOT NULL DEFAULT 'totp',
    secret_key  VARCHAR(255)    NULL,
    backup_codes JSON           NULL,
    is_enabled  TINYINT(1)      NOT NULL DEFAULT 0,
    verified_at DATETIME        NULL,
    created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP
                  ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    INDEX idx_2fa_user_id (user_id),

    CONSTRAINT fk_2fa_user
      FOREIGN KEY (user_id) REFERENCES users(id)
      ON DELETE CASCADE
) ENGINE=InnoDB;


-- ============================================================
--  STORED PROCEDURE: register_user
-- ============================================================
DELIMITER $$

CREATE PROCEDURE register_user (
    IN  p_first_name    VARCHAR(60),
    IN  p_last_name     VARCHAR(60),
    IN  p_email         VARCHAR(255),
    IN  p_password_hash VARCHAR(255),
    IN  p_organisation  VARCHAR(120),
    OUT p_user_id       INT UNSIGNED,
    OUT p_status        VARCHAR(50)
)
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        SET p_status  = 'ERROR';
        SET p_user_id = 0;
    END;

    START TRANSACTION;

    IF EXISTS (SELECT 1 FROM users WHERE email = p_email AND deleted_at IS NULL) THEN
        SET p_status  = 'EMAIL_ALREADY_EXISTS';
        SET p_user_id = 0;
        ROLLBACK;
    ELSE
        INSERT INTO users (first_name, last_name, email, password_hash, organisation)
        VALUES (p_first_name, p_last_name, p_email, p_password_hash, p_organisation);

        SET p_user_id = LAST_INSERT_ID();

        INSERT INTO user_preferences (user_id) VALUES (p_user_id);

        INSERT INTO user_audit_log (user_id, action, description)
        VALUES (p_user_id, 'REGISTER', 'New user account created');

        SET p_status = 'SUCCESS';
        COMMIT;
    END IF;
END$$

DELIMITER ;


-- ============================================================
--  STORED PROCEDURE: login_user
-- ============================================================
DELIMITER $$

CREATE PROCEDURE login_user (
    IN  p_email       VARCHAR(255),
    IN  p_ip_address  VARCHAR(45),
    IN  p_user_agent  TEXT,
    OUT p_user_id     INT UNSIGNED,
    OUT p_status      VARCHAR(50),
    OUT p_role        VARCHAR(20)
)
BEGIN
    DECLARE v_user_id           INT UNSIGNED DEFAULT 0;
    DECLARE v_is_active         TINYINT(1)   DEFAULT 0;
    DECLARE v_is_email_verified TINYINT(1)   DEFAULT 0;
    DECLARE v_role              VARCHAR(20)  DEFAULT '';
    DECLARE v_recent_failures   INT          DEFAULT 0;
    DECLARE v_locked            INT          DEFAULT 0;

    SELECT id, is_active, is_email_verified, role
    INTO   v_user_id, v_is_active, v_is_email_verified, v_role
    FROM   users
    WHERE  email = p_email AND deleted_at IS NULL
    LIMIT  1;

    IF v_user_id = 0 THEN
        INSERT INTO login_attempts (email, ip_address, user_agent, success, failure_reason)
        VALUES (p_email, p_ip_address, p_user_agent, 0, 'user_not_found');
        SET p_status  = 'USER_NOT_FOUND';
        SET p_user_id = 0;
        SET p_role    = '';

    ELSEIF v_is_active = 0 THEN
        INSERT INTO login_attempts (email, user_id, ip_address, user_agent, success, failure_reason)
        VALUES (p_email, v_user_id, p_ip_address, p_user_agent, 0, 'account_inactive');
        SET p_status  = 'ACCOUNT_INACTIVE';
        SET p_user_id = 0;
        SET p_role    = '';

    ELSE
        SELECT COUNT(*) INTO v_locked
        FROM   account_lockouts
        WHERE  user_id   = v_user_id
          AND  unlock_at > NOW()
          AND (unlocked_early = 0 OR unlocked_at IS NULL);

        IF v_locked > 0 THEN
            INSERT INTO login_attempts (email, user_id, ip_address, user_agent, success, failure_reason)
            VALUES (p_email, v_user_id, p_ip_address, p_user_agent, 0, 'account_locked');
            SET p_status  = 'ACCOUNT_LOCKED';
            SET p_user_id = 0;
            SET p_role    = '';

        ELSE
            SELECT COUNT(*) INTO v_recent_failures
            FROM   login_attempts
            WHERE  email        = p_email
              AND  success      = 0
              AND  attempted_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE);

            IF v_recent_failures >= 5 THEN
                INSERT INTO account_lockouts (user_id, locked_at, unlock_at, reason)
                VALUES (v_user_id, NOW(), DATE_ADD(NOW(), INTERVAL 30 MINUTE),
                        'Too many failed login attempts');

                INSERT INTO login_attempts (email, user_id, ip_address, user_agent, success, failure_reason)
                VALUES (p_email, v_user_id, p_ip_address, p_user_agent, 0, 'too_many_attempts');

                INSERT INTO user_audit_log (user_id, action, description, ip_address)
                VALUES (v_user_id, 'ACCOUNT_LOCKED', 'Auto-locked after 5 failed attempts', p_ip_address);

                SET p_status  = 'TOO_MANY_ATTEMPTS';
                SET p_user_id = 0;
                SET p_role    = '';

            ELSE
                SET p_status  = 'CREDENTIALS_OK';
                SET p_user_id = v_user_id;
                SET p_role    = v_role;
            END IF;
        END IF;
    END IF;
END$$

DELIMITER ;


-- ============================================================
--  STORED PROCEDURE: record_successful_login
-- ============================================================
DELIMITER $$

CREATE PROCEDURE record_successful_login (
    IN p_user_id    INT UNSIGNED,
    IN p_email      VARCHAR(255),
    IN p_ip_address VARCHAR(45),
    IN p_user_agent TEXT,
    IN p_token_hash VARCHAR(255),
    IN p_expires_at DATETIME
)
BEGIN
    INSERT INTO login_attempts (email, user_id, ip_address, user_agent, success)
    VALUES (p_email, p_user_id, p_ip_address, p_user_agent, 1);

    INSERT INTO sessions (user_id, token_hash, ip_address, user_agent, expires_at)
    VALUES (p_user_id, p_token_hash, p_ip_address, p_user_agent, p_expires_at);

    INSERT INTO user_audit_log (user_id, action, description, ip_address)
    VALUES (p_user_id, 'LOGIN', 'Successful login', p_ip_address);
END$$

DELIMITER ;


-- ============================================================
--  STORED PROCEDURE: logout_user
-- ============================================================
DELIMITER $$

CREATE PROCEDURE logout_user (
    IN p_token_hash VARCHAR(255),
    IN p_ip_address VARCHAR(45)
)
BEGIN
    DECLARE v_user_id INT UNSIGNED DEFAULT 0;

    SELECT user_id INTO v_user_id
    FROM   sessions
    WHERE  token_hash = p_token_hash AND is_active = 1
    LIMIT  1;

    IF v_user_id > 0 THEN
        UPDATE sessions
        SET    is_active  = 0,
               revoked_at = NOW()
        WHERE  token_hash = p_token_hash;

        INSERT INTO user_audit_log (user_id, action, description, ip_address)
        VALUES (v_user_id, 'LOGOUT', 'Session revoked', p_ip_address);
    END IF;
END$$

DELIMITER ;


-- ============================================================
--  STORED PROCEDURE: request_password_reset
-- ============================================================
DELIMITER $$

CREATE PROCEDURE request_password_reset (
    IN  p_email      VARCHAR(255),
    IN  p_token      VARCHAR(128),
    IN  p_ip_address VARCHAR(45),
    OUT p_status     VARCHAR(50)
)
BEGIN
    DECLARE v_user_id INT UNSIGNED DEFAULT 0;

    SELECT id INTO v_user_id
    FROM   users
    WHERE  email = p_email AND is_active = 1 AND deleted_at IS NULL
    LIMIT  1;

    IF v_user_id = 0 THEN
        SET p_status = 'EMAIL_SENT';
    ELSE
        UPDATE password_reset_tokens
        SET    used_at = NOW()
        WHERE  user_id = v_user_id AND used_at IS NULL;

        INSERT INTO password_reset_tokens (user_id, token, expires_at, ip_address)
        VALUES (v_user_id, p_token, DATE_ADD(NOW(), INTERVAL 1 HOUR), p_ip_address);

        INSERT INTO user_audit_log (user_id, action, description, ip_address)
        VALUES (v_user_id, 'PASSWORD_RESET_REQUESTED', 'Password reset token issued', p_ip_address);

        SET p_status = 'EMAIL_SENT';
    END IF;
END$$

DELIMITER ;


-- ============================================================
--  STORED PROCEDURE: reset_password
-- ============================================================
DELIMITER $$

CREATE PROCEDURE reset_password (
    IN  p_token         VARCHAR(128),
    IN  p_password_hash VARCHAR(255),
    IN  p_ip_address    VARCHAR(45),
    OUT p_status        VARCHAR(50)
)
BEGIN
    DECLARE v_user_id INT UNSIGNED DEFAULT 0;
    DECLARE v_used_at DATETIME     DEFAULT NULL;
    DECLARE v_expires DATETIME     DEFAULT NULL;

    SELECT user_id, used_at, expires_at
    INTO   v_user_id, v_used_at, v_expires
    FROM   password_reset_tokens
    WHERE  token = p_token
    LIMIT  1;

    IF v_user_id = 0 THEN
        SET p_status = 'INVALID_TOKEN';

    ELSEIF v_used_at IS NOT NULL THEN
        SET p_status = 'TOKEN_ALREADY_USED';

    ELSEIF v_expires < NOW() THEN
        SET p_status = 'TOKEN_EXPIRED';

    ELSE
        START TRANSACTION;

        UPDATE users
        SET    password_hash = p_password_hash,
               updated_at    = NOW()
        WHERE  id = v_user_id;

        UPDATE password_reset_tokens
        SET    used_at = NOW()
        WHERE  token   = p_token;

        UPDATE sessions
        SET    is_active  = 0,
               revoked_at = NOW()
        WHERE  user_id    = v_user_id AND is_active = 1;

        INSERT INTO user_audit_log (user_id, action, description, ip_address)
        VALUES (v_user_id, 'PASSWORD_RESET', 'Password changed via reset token', p_ip_address);

        COMMIT;
        SET p_status = 'SUCCESS';
    END IF;
END$$

DELIMITER ;


-- ============================================================
--  VIEWS
-- ============================================================

CREATE OR REPLACE VIEW v_active_users AS
SELECT
    u.id,
    u.uuid,
    u.first_name,
    u.last_name,
    CONCAT(u.first_name, ' ', u.last_name) AS full_name,
    u.email,
    u.organisation,
    u.role,
    u.is_email_verified,
    u.created_at,
    u.updated_at,
    CASE WHEN al.id IS NOT NULL THEN 1 ELSE 0 END AS is_currently_locked,
    al.unlock_at
FROM users u
LEFT JOIN account_lockouts al
       ON al.user_id      = u.id
      AND al.unlock_at    > NOW()
      AND al.unlocked_early = 0
WHERE u.is_active  = 1
  AND u.deleted_at IS NULL;


CREATE OR REPLACE VIEW v_recent_login_activity AS
SELECT
    la.id,
    la.email,
    u.first_name,
    u.last_name,
    la.ip_address,
    la.success,
    la.failure_reason,
    la.attempted_at
FROM login_attempts la
LEFT JOIN users u ON u.id = la.user_id
WHERE la.attempted_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
ORDER BY la.attempted_at DESC;


CREATE OR REPLACE VIEW v_active_sessions AS
SELECT
    s.id,
    s.user_id,
    CONCAT(u.first_name, ' ', u.last_name) AS full_name,
    u.email,
    s.ip_address,
    s.device_name,
    s.last_active_at,
    s.expires_at,
    s.created_at
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.is_active  = 1
  AND s.expires_at > NOW()
ORDER BY s.last_active_at DESC;


-- ============================================================
--  SEED DATA — default admin account
--  Replace the password hash before going to production.
--  Generate hash in Python:
--    import bcrypt
--    bcrypt.hashpw(b'Admin@123', bcrypt.gensalt()).decode()
-- ============================================================
INSERT INTO users
    (first_name, last_name, email, password_hash, organisation, role, is_active, is_email_verified)
VALUES
    ('Sentinel', 'Admin',
     'admin@sentinel.local',
     '$2b$12$PLACEHOLDER_REPLACE_WITH_REAL_BCRYPT_HASH',
     'Sentinel IDS', 'admin', 1, 1);

INSERT INTO user_preferences (user_id)
VALUES (LAST_INSERT_ID());

INSERT INTO user_audit_log (user_id, action, description)
VALUES (LAST_INSERT_ID(), 'REGISTER', 'Default admin account seeded');


-- ============================================================
--  EVENT SCHEDULER — enable it first
-- ============================================================
SET GLOBAL event_scheduler = ON;


-- ============================================================
--  CLEANUP EVENT — auto-purge expired tokens & old attempts
--  Runs daily at 02:00
-- ============================================================
DELIMITER $$

CREATE EVENT IF NOT EXISTS evt_nightly_cleanup
ON SCHEDULE EVERY 1 DAY
STARTS (TIMESTAMP(CURRENT_DATE) + INTERVAL 2 HOUR)
DO
BEGIN
    -- Remove expired unused reset tokens older than 24 hours
    DELETE FROM password_reset_tokens
    WHERE  expires_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)
      AND  used_at IS NULL;

    -- Remove expired email verification tokens older than 48 hours
    DELETE FROM email_verifications
    WHERE  expires_at < DATE_SUB(NOW(), INTERVAL 48 HOUR)
      AND  used_at IS NULL;

    -- Remove login attempt records older than 90 days
    DELETE FROM login_attempts
    WHERE  attempted_at < DATE_SUB(NOW(), INTERVAL 90 DAY);

    -- Expire old inactive sessions
    DELETE FROM sessions
    WHERE  expires_at < DATE_SUB(NOW(), INTERVAL 30 DAY)
      AND  is_active = 0;
END$$

DELIMITER ;


-- ============================================================
--  VERIFY EVERYTHING WAS CREATED  (run after the script)
-- ============================================================
-- SHOW TABLES;
-- SHOW PROCEDURE STATUS WHERE Db = 'sentinel_auth';
-- SHOW EVENTS FROM sentinel_auth;


-- ============================================================
--  QUICK REFERENCE
-- ============================================================
--
--  REGISTER A USER:
--    CALL register_user('John','Doe','john@example.com','<bcrypt_hash>','Acme Corp', @uid, @status);
--    SELECT @uid, @status;
--
--  LOGIN (step 1 — check account status):
--    CALL login_user('john@example.com','192.168.1.1','Mozilla/5.0', @uid, @status, @role);
--    SELECT @uid, @status, @role;
--    -- If @status = 'CREDENTIALS_OK', verify password hash in app layer, then:
--
--  LOGIN (step 2 — record success):
--    CALL record_successful_login(@uid,'john@example.com','192.168.1.1','Mozilla/5.0','<sha256_of_jwt>','2025-12-31 00:00:00');
--
--  LOGOUT:
--    CALL logout_user('<sha256_of_jwt>', '192.168.1.1');
--
--  REQUEST PASSWORD RESET:
--    CALL request_password_reset('john@example.com','<random_token>','192.168.1.1', @status);
--    SELECT @status;
--
--  RESET PASSWORD:
--    CALL reset_password('<token>','<new_bcrypt_hash>','192.168.1.1', @status);
--    SELECT @status;
--
-- ============================================================
