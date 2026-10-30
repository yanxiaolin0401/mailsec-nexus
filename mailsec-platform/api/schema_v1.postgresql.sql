-- Platform schema v1. Apply once on an empty PostgreSQL database.
CREATE TABLE login_attempts (
	id SERIAL NOT NULL, 
	key VARCHAR(64) NOT NULL, 
	count INTEGER NOT NULL, 
	window_started_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	locked_until TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_login_attempt_key UNIQUE (key)
);

CREATE TABLE schema_version (
	version SERIAL NOT NULL, 
	PRIMARY KEY (version)
);

CREATE TABLE tenants (
	id SERIAL NOT NULL, 
	name VARCHAR(160) NOT NULL, 
	slug VARCHAR(80) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (slug)
);

CREATE TABLE users (
	id SERIAL NOT NULL, 
	username VARCHAR(80) NOT NULL, 
	display_name VARCHAR(160) NOT NULL, 
	role VARCHAR(8) NOT NULL, 
	tenant_id INTEGER, 
	password_hash VARCHAR(256) NOT NULL, 
	is_active BOOLEAN NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT ck_user_role_tenant CHECK ((role = 'admin' AND tenant_id IS NULL) OR (role = 'user' AND tenant_id IS NOT NULL)), 
	UNIQUE (username), 
	FOREIGN KEY(tenant_id) REFERENCES tenants (id) ON DELETE RESTRICT
);

CREATE INDEX ix_users_tenant_id ON users (tenant_id);

CREATE TABLE audit_events (
	id SERIAL NOT NULL, 
	actor_user_id INTEGER, 
	action VARCHAR(80) NOT NULL, 
	target VARCHAR(160) NOT NULL, 
	detail TEXT NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(actor_user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE TABLE sessions (
	id SERIAL NOT NULL, 
	user_id INTEGER NOT NULL, 
	token_hash VARCHAR(64) NOT NULL, 
	csrf_token_hash VARCHAR(64) NOT NULL, 
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	revoked_at TIMESTAMP WITH TIME ZONE, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE, 
	UNIQUE (token_hash)
);

CREATE INDEX ix_sessions_user_id ON sessions (user_id);

INSERT INTO schema_version (version) VALUES (1);
