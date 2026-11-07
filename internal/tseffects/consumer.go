// Package tseffects receives effective T&S decisions (ts.action.effective.v1)
// and applies them to the user-owned standing through the single database
// entry point. The database records each action once and resolves the
// Keycloak principal; this package only validates the envelope, commits
// before acknowledging and classifies failures.
package tseffects

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/lib/pq"
	amqp "github.com/rabbitmq/amqp091-go"
)

const (
	EventType = "ts.action.effective.v1"
	Queue     = "rac.user.ts_effects"
)

var eventID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Disposition is what happens to a delivery after handling it.
type Disposition int

const (
	Ack        Disposition = iota // committed or an exact replay
	Requeue                       // transient: retried until the queue's delivery limit
	DeadLetter                    // invalid or conflicting: kept for investigation, never retried
)

type Store interface {
	Apply(ctx context.Context, event string, body []byte) error
}

// Postgres calls only standing.apply_ts_effect inside its own transaction.
type Postgres struct {
	DB     *sql.DB
	Policy string
}

func (p Postgres) Apply(ctx context.Context, event string, body []byte) error {
	tx, err := p.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var result []byte
	if err := tx.QueryRowContext(ctx, `SELECT standing.apply_ts_effect($1,$2::jsonb,$3)`, event, string(body), p.Policy).Scan(&result); err != nil {
		return err
	}
	return tx.Commit()
}

// Classify maps a store error to a disposition. Serialization failures and
// out-of-order revocations (40001) are retried; invalid commands, conflicting
// redeliveries and unknown principals go to the failed queue.
func Classify(err error) Disposition {
	if err == nil {
		return Ack
	}
	var dbError *pq.Error
	if errors.As(err, &dbError) {
		switch dbError.Code {
		case "40001", "40P01", "55P03", "57014":
			return Requeue
		case "22023", "22P02", "23505", "23514", "P0002", "42501":
			return DeadLetter
		}
		if dbError.Code.Class() == "08" || dbError.Code.Class() == "53" || dbError.Code.Class() == "57" {
			return Requeue
		}
		return DeadLetter
	}
	// Connection loss, timeouts and driver errors: the commit did not happen
	// or is uncertain; the database replay rules make a retry safe.
	return Requeue
}

// Handle validates the envelope before touching the store.
func Handle(ctx context.Context, store Store, body []byte, id, typ, contentType string) Disposition {
	if typ != EventType || contentType != "application/json" || !eventID.MatchString(id) || len(body) == 0 || len(body) > 4096 {
		return DeadLetter
	}
	return Classify(store.Apply(ctx, id, body))
}

type Consumer struct {
	Store     Store
	Connected atomic.Bool
	Applied   atomic.Uint64
	Retried   atomic.Uint64
	Failed    atomic.Uint64
}

// Session consumes until the context ends or the connection fails; the caller
// reconnects. Prefetch 1 keeps per-principal order from the relay.
func (c *Consumer) Session(ctx context.Context, url string) error {
	conn, err := amqp.DialConfig(url, amqp.Config{Heartbeat: 10 * time.Second, Dial: func(network, addr string) (net.Conn, error) {
		socket, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		if err = socket.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			socket.Close()
			return nil, err
		}
		return socket, nil
	}})
	if err != nil {
		return errors.New("broker_unavailable")
	}
	defer conn.Close()
	ch, err := conn.Channel()
	if err != nil {
		return errors.New("channel_unavailable")
	}
	defer ch.Close()
	if err = ch.Qos(1, 0, false); err != nil {
		return errors.New("qos_unavailable")
	}
	deliveries, err := ch.Consume(Queue, "", false, false, false, false, nil)
	if err != nil {
		return errors.New("queue_unavailable")
	}
	c.Connected.Store(true)
	defer c.Connected.Store(false)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case d, ok := <-deliveries:
			if !ok {
				return errors.New("delivery_closed")
			}
			bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
			disposition := Handle(bounded, c.Store, d.Body, d.MessageId, d.Type, d.ContentType)
			cancel()
			switch disposition {
			case Ack:
				err = d.Ack(false)
				c.Applied.Add(1)
			case Requeue:
				err = d.Nack(false, true)
				c.Retried.Add(1)
			default:
				// The queue policy dead-letters rejected deliveries at least once.
				err = d.Reject(false)
				c.Failed.Add(1)
			}
			if err != nil {
				return errors.New("acknowledgement_failed")
			}
		}
	}
}
