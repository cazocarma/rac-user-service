// Command ts-effects applies effective T&S decisions to user standing. It is
// opt-in, limited to DEV/test until activation is approved, uses a
// function-only login and reads credentials only from mounted files.
package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	staffdb "github.com/cazocarma/rac-platform/staff/postgres"
	"github.com/cazocarma/rac-user-service/internal/secretfile"
	"github.com/cazocarma/rac-user-service/internal/tseffects"
	_ "github.com/lib/pq"
)

var policyPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func prepare(ctx context.Context) (*tseffects.Consumer, *sql.DB, string, error) {
	if os.Getenv("TS_EFFECTS_ENABLED") != "true" {
		return nil, nil, "", errors.New("consumer not enabled")
	}
	switch os.Getenv("RAC_ENV") {
	case "dev", "test":
	default:
		return nil, nil, "", errors.New("consumer activation not approved for this environment")
	}
	policy := os.Getenv("TS_EFFECTS_POLICY_VERSION")
	if !policyPattern.MatchString(policy) {
		return nil, nil, "", errors.New("audit policy reference required")
	}
	dsn, err := secretfile.ReadEnvironment("TS_EFFECTS_DATABASE_URL")
	if err != nil {
		return nil, nil, "", err
	}
	broker, err := secretfile.ReadEnvironment("TS_EFFECTS_AMQP_URL")
	if err != nil {
		return nil, nil, "", err
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, nil, "", err
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)
	authority := staffdb.RolePolicy{Functions: []string{"standing.apply_ts_effect(uuid,jsonb,uuid)", "standing.refresh_ts_standing(uuid,uuid,uuid)"}}
	if err := staffdb.CheckRole(ctx, db, authority); err != nil {
		db.Close()
		return nil, nil, "", errors.New("consumer database privileges not isolated")
	}
	return &tseffects.Consumer{Store: tseffects.Postgres{DB: db, Policy: policy}}, db, broker, nil
}

func run(ctx context.Context) error {
	startup, cancel := context.WithTimeout(ctx, 20*time.Second)
	consumer, db, broker, err := prepare(startup)
	cancel()
	if err != nil {
		return err
	}
	defer db.Close()
	log.Print("ts effects consumer started: commits before acknowledging")
	failures := 0
	for ctx.Err() == nil {
		err := consumer.Session(ctx, broker)
		if ctx.Err() != nil {
			return nil
		}
		failures++
		if err != nil {
			log.Print("ts effects session ended; reconnecting")
		}
		timer := time.NewTimer(time.Second << min(failures, 5))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		if consumer.Applied.Load() > 0 {
			failures = 0
		}
	}
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		log.Print("ts effects consumer startup refused; check isolated configuration")
		os.Exit(1)
	}
}
