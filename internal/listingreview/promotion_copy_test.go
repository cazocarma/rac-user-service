package listingreview

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cazocarma/rac-platform/staff"
	"github.com/cazocarma/rac-user-service/internal/photostore"
)

type copyFixtureDestination struct {
	create  func(context.Context, string, []byte) (string, error)
	current func(context.Context, string) (string, error)
	version func(context.Context, string, string) ([]byte, error)
}

func (d copyFixtureDestination) Create(c context.Context, k string, b []byte) (string, error) {
	return d.create(c, k, b)
}
func (d copyFixtureDestination) CurrentVersion(c context.Context, k string) (string, error) {
	return d.current(c, k)
}
func (d copyFixtureDestination) Version(c context.Context, k, v string) ([]byte, error) {
	return d.version(c, k, v)
}

func copyFixture() (promotionIntent, staff.Session, []byte, time.Time) {
	now := time.Now()
	data := []byte{0xff, 0xd8, 0xff, 0x01}
	digest := sha256.Sum256(data)
	intent := promotionIntent{committed: true, ID: "11111111-1111-4111-8111-111111111111", Attempt: "22222222-2222-4222-8222-222222222222",
		Actor: "77777777-7777-4777-8777-777777777777", SourceKey: strings.Repeat("c", 32) + ".jpg", DestinationKey: strings.Repeat("1", 12) + "41118111" + strings.Repeat("1", 12) + ".jpg",
		NormalizedSHA256: hex.EncodeToString(digest[:]), NormalizedSize: len(data), ExpiresAt: now.Add(2 * time.Minute)}
	session := staff.Session{Subject: intent.Actor, Permissions: []staff.Permission{staff.ListingsReview}, AuthenticatedAt: now.Add(-30 * time.Second), ExpiresAt: now.Add(4 * time.Minute)}
	return intent, session, data, now
}

func TestPromotionCopyVerifiesPinnedBytesAndRecoversAfterLostACK(t *testing.T) {
	intent, session, data, clock := copyFixture()
	stored := []byte(nil)
	created := false
	reads := 0
	recoveries := 0
	source := previewFixtureStore{get: func(ctx context.Context, key string) ([]byte, error) {
		if key != intent.SourceKey {
			t.Fatal("source was not bound to prepared result")
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 20*time.Second {
			t.Fatal("unbounded copy context")
		}
		return data, nil
	}}
	destination := copyFixtureDestination{
		create: func(_ context.Context, key string, body []byte) (string, error) {
			if key != intent.DestinationKey || !bytes.Equal(body, data) {
				t.Fatal("copied a different key or bytes")
			}
			if created {
				return "", photostore.ErrExists
			}
			created = true
			stored = bytes.Clone(body)
			return "", errors.New("synthetic ACK lost after persistence")
		},
		current: func(_ context.Context, key string) (string, error) {
			recoveries++
			return "opaque-provider-version-1", nil
		},
		version: func(_ context.Context, key, version string) ([]byte, error) {
			reads++
			if version != "opaque-provider-version-1" || key != intent.DestinationKey {
				t.Fatal("unpinned readback")
			}
			return bytes.Clone(stored), nil
		},
	}
	if receipt, err := copyPreparedPhoto(context.Background(), session, intent, source, destination, func() time.Time { return clock }); err == nil || receipt.version != "" || !created || reads != 0 {
		t.Fatal("unknown ACK became success or removed stored bytes", err)
	}
	retry := intent
	retry.Attempt = "33333333-3333-4333-8333-333333333333"
	receipt, err := copyPreparedPhoto(context.Background(), session, retry, source, destination, func() time.Time { return clock })
	if err != nil || receipt.intent != intent.ID || receipt.attempt != retry.Attempt || receipt.key != intent.DestinationKey ||
		receipt.version != "opaque-provider-version-1" || receipt.digest != sha256.Sum256(data) || receipt.size != len(data) || reads != 1 || recoveries != 1 {
		t.Fatal("retry did not recover exact version and verify bytes", err)
	}
}

func TestPromotionCopySuccessfulPutStillRequiresReadback(t *testing.T) {
	for _, fault := range []string{"none", "corrupt", "truncated", "read-error", "null-version", "recovery-error"} {
		t.Run(fault, func(t *testing.T) {
			intent, session, data, clock := copyFixture()
			writes, reads := 0, 0
			source := previewFixtureStore{get: func(context.Context, string) ([]byte, error) { return data, nil }}
			destination := copyFixtureDestination{
				create: func(context.Context, string, []byte) (string, error) {
					writes++
					if fault == "null-version" {
						return "null", nil
					}
					if fault == "recovery-error" {
						return "", photostore.ErrExists
					}
					return "version-1", nil
				},
				current: func(context.Context, string) (string, error) { return "", errors.New("private storage diagnostic") },
				version: func(_ context.Context, _ string, version string) ([]byte, error) {
					reads++
					if version != "version-1" {
						t.Fatal("missing explicit version")
					}
					switch fault {
					case "corrupt":
						return []byte{0xff, 0xd8, 0xff, 0x02}, nil
					case "truncated":
						return data[:3], nil
					case "read-error":
						return nil, errors.New("private storage diagnostic")
					}
					return bytes.Clone(data), nil
				},
			}
			receipt, err := copyPreparedPhoto(context.Background(), session, intent, source, destination, func() time.Time { return clock })
			if fault == "none" {
				if err != nil || receipt.version != "version-1" || reads != 1 || writes != 1 {
					t.Fatal("successful PUT was not verified", err)
				}
			} else if err == nil || receipt.version != "" || strings.Contains(err.Error(), "diagnostic") {
				t.Fatal("unverified object yielded receipt or diagnostic", err)
			}
		})
	}
}

func TestPromotionCopyRejectsSourceAndUncommittedMetadataBeforeWrite(t *testing.T) {
	for _, fault := range []string{"uncommitted", "json-roundtrip", "source-error", "digest", "size", "not-jpeg", "wrong-actor", "no-permission", "expired", "cancelled"} {
		t.Run(fault, func(t *testing.T) {
			intent, session, data, clock := copyFixture()
			gets, writes := 0, 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch fault {
			case "uncommitted":
				intent.committed = false
			case "json-roundtrip":
				raw, _ := json.Marshal(intent)
				intent = promotionIntent{}
				if err := json.Unmarshal(raw, &intent); err != nil {
					t.Fatal(err)
				}
			case "digest":
				intent.NormalizedSHA256 = strings.Repeat("a", 64)
			case "size":
				intent.NormalizedSize++
			case "not-jpeg":
				data = []byte("not-jpeg")
				digest := sha256.Sum256(data)
				intent.NormalizedSize = len(data)
				intent.NormalizedSHA256 = hex.EncodeToString(digest[:])
			case "wrong-actor":
				session.Subject = "88888888-8888-4888-8888-888888888888"
			case "no-permission":
				session.Permissions = nil
			case "expired":
				intent.ExpiresAt = clock
			case "cancelled":
				cancel()
			}
			source := previewFixtureStore{get: func(context.Context, string) ([]byte, error) {
				gets++
				if fault == "source-error" {
					return nil, errors.New("private driver diagnostic")
				}
				return data, nil
			}}
			destination := copyFixtureDestination{create: func(context.Context, string, []byte) (string, error) { writes++; return "version-1", nil }}
			if receipt, err := copyPreparedPhoto(ctx, session, intent, source, destination, func() time.Time { return clock }); err == nil || receipt.version != "" || writes != 0 {
				t.Fatal("invalid input initiated destination write", fault, err, writes)
			}
			if (fault == "uncommitted" || fault == "json-roundtrip" || fault == "wrong-actor" || fault == "no-permission" || fault == "expired" || fault == "cancelled") && gets != 0 {
				t.Fatal("unauthorized metadata read source", fault)
			}
		})
	}
}

func TestPromotionCopyRechecksAuthorizationAcrossIO(t *testing.T) {
	for _, stage := range []string{"after-source", "after-destination"} {
		t.Run(stage, func(t *testing.T) {
			intent, session, data, clock := copyFixture()
			writes := 0
			source := previewFixtureStore{get: func(context.Context, string) ([]byte, error) {
				if stage == "after-source" {
					clock = clock.Add(3 * time.Minute)
				}
				return data, nil
			}}
			destination := copyFixtureDestination{
				create: func(context.Context, string, []byte) (string, error) { writes++; return "version-1", nil },
				version: func(context.Context, string, string) ([]byte, error) {
					clock = clock.Add(6 * time.Minute)
					return data, nil
				},
			}
			if receipt, err := copyPreparedPhoto(context.Background(), session, intent, source, destination, func() time.Time { return clock }); err == nil || receipt.version != "" {
				t.Fatal("expired authorization yielded receipt", stage)
			}
			if stage == "after-source" && writes != 0 {
				t.Fatal("expired attempt initiated copy")
			}
			if stage == "after-destination" && writes != 1 {
				t.Fatal("test never persisted private copy")
			}
		})
	}
}
