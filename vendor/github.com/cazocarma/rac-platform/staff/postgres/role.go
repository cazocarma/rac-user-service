// Package postgres checks the shared database boundary for private staff
// ingresses. It owns no business tables, credentials or provisioning side effects.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

var ErrRoleNotIsolated = errors.New("database function role not isolated")
var ErrRolePolicy = errors.New("invalid function-only database role policy")
var schemaName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

type RolePolicy struct {
	// Fully qualified, fixed function signatures reviewed with the ingress.
	Functions      []string
	ForbiddenRoles []string
}

// CheckRole rejects effective application data privileges, ownership and
// unexpected executable functions, including privileges inherited from PUBLIC.
// Inherited extension defaults (PostGIS/pgcrypto) are not application authority;
// an explicit extra grant to this login is still rejected. TEMP policy remains
// the database provisioner's responsibility; this checks the function boundary.
func CheckRole(ctx context.Context, db *sql.DB, policy RolePolicy) error {
	if len(policy.Functions) == 0 || len(policy.Functions) > 64 {
		return ErrRolePolicy
	}
	seen := map[string]bool{}
	for _, signature := range policy.Functions {
		namespace, rest, ok := strings.Cut(signature, ".")
		if !ok || !schemaName.MatchString(namespace) || strings.HasPrefix(namespace, "pg_") || namespace == "information_schema" || !strings.Contains(rest, "(") || !strings.HasSuffix(rest, ")") || len(signature) > 512 || seen[signature] {
			return ErrRolePolicy
		}
		seen[signature] = true
	}
	if db == nil {
		return ErrRoleNotIsolated
	}
	functions, _ := json.Marshal(policy.Functions)
	roles, _ := json.Marshal(policy.ForbiddenRoles)
	if policy.ForbiddenRoles == nil {
		roles = []byte("[]")
	}
	var allowed bool
	err := db.QueryRowContext(ctx, roleSQL, string(functions), string(roles)).Scan(&allowed)
	if err != nil || !allowed {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrRoleNotIsolated
	}
	return nil
}

const roleSQL = `WITH allowed AS (
 SELECT to_regprocedure(value)::oid AS id FROM jsonb_array_elements_text($1::jsonb)
), app_schemas AS (
 SELECT oid,nspowner FROM pg_namespace WHERE nspname<>'information_schema' AND nspname !~ '^pg_'
), app_functions AS (
 SELECT p.*,EXISTS(SELECT FROM pg_depend d WHERE d.classid='pg_proc'::regclass AND d.objid=p.oid AND d.deptype='e') AS extension
 FROM pg_proc p JOIN app_schemas n ON n.oid=p.pronamespace
), app_relations AS (
 SELECT c.*,EXISTS(SELECT FROM pg_depend d WHERE d.classid='pg_class'::regclass AND d.objid=c.oid AND d.deptype='e') AS extension
 FROM pg_class c JOIN app_schemas n ON n.oid=c.relnamespace
)
SELECT current_user=session_user AND r.rolcanlogin
 AND NOT(r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
 AND NOT EXISTS(SELECT FROM pg_auth_members m WHERE m.member=r.oid)
 AND r.rolname NOT IN(SELECT value FROM jsonb_array_elements_text($2::jsonb))
 AND NOT EXISTS(SELECT FROM pg_database d WHERE d.datname=current_database() AND d.datdba=r.oid)
 AND NOT has_database_privilege(session_user,current_database(),'CREATE')
 AND NOT EXISTS(SELECT FROM app_schemas n WHERE n.nspowner=r.oid OR has_schema_privilege(session_user,n.oid,'CREATE'))
 AND NOT EXISTS(SELECT FROM app_relations c
  WHERE c.relkind IN('r','p','v','m','f')
  AND(c.relowner=r.oid
   OR(NOT c.extension AND(has_table_privilege(session_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
      OR has_any_column_privilege(session_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
   OR EXISTS(SELECT FROM aclexplode(c.relacl) acl WHERE acl.grantee=r.oid)
   OR EXISTS(SELECT FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) acl
             WHERE a.attrelid=c.oid AND acl.grantee=r.oid)))
 AND NOT EXISTS(SELECT FROM app_relations c
  WHERE c.relkind='S' AND(c.relowner=r.oid
   OR(NOT c.extension AND has_sequence_privilege(session_user,c.oid,'SELECT,UPDATE,USAGE'))
   OR EXISTS(SELECT FROM aclexplode(c.relacl) acl WHERE acl.grantee=r.oid)))
 AND NOT EXISTS(SELECT FROM allowed a LEFT JOIN pg_proc p ON p.oid=a.id
  WHERE a.id IS NULL OR has_function_privilege(session_user,a.id,'EXECUTE') IS NOT TRUE
    OR has_schema_privilege(session_user,p.pronamespace,'USAGE') IS NOT TRUE
    OR NOT p.prosecdef OR (p.proconfig @> ARRAY['search_path=pg_catalog']) IS NOT TRUE)
 AND (SELECT count(DISTINCT id) FROM allowed)=jsonb_array_length($1::jsonb)
 AND NOT EXISTS(SELECT FROM app_functions p WHERE p.proowner=r.oid
  OR(p.oid NOT IN(SELECT id FROM allowed) AND (
   (NOT p.extension AND has_function_privilege(session_user,p.oid,'EXECUTE'))
   OR EXISTS(SELECT FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl
             WHERE acl.grantee=r.oid AND acl.privilege_type='EXECUTE'))))
FROM pg_roles r WHERE r.rolname=session_user`
