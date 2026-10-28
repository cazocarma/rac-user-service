package editorial

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/cazocarma/rac-platform/staff"
	"github.com/cazocarma/rac-user-service/internal/attestations"
	"github.com/lib/pq"
)

func assessmentFixture() attestations.Content {
	content := attestations.Content{}
	for _, id := range []string{"no_illicit_substances", "no_sexual_services", "catalog_only", "adults_only", "enforcement_and_appeal"} {
		content.Statements = append(content.Statements, attestations.Statement{ID: id, Text: "Declaración sintética, no definitiva."})
	}
	for _, id := range []string{"one", "two", "three"} {
		content.Questions = append(content.Questions, attestations.Question{ID: id, Text: "Escenario sintético", CorrectOption: "report", Options: []attestations.Option{{ID: "report", Text: "Rechazar y reportar"}, {ID: "continue", Text: "Continuar"}}})
	}
	return content
}
func testAssessmentBundleHTTP(t *testing.T, admin *sql.DB, s *Server, token func(string, string, string) string) {
	t.Helper()
	handler := s.Handler()
	uuid := func() string {
		t.Helper()
		var id string
		if admin.QueryRow("SELECT gen_random_uuid()::text").Scan(&id) != nil {
			t.Fatal("fixture id unavailable")
		}
		return id
	}
	send := func(method, path, subject string, body any, want int) *http.Response {
		t.Helper()
		w := request(t, handler, method, path, token(subject, "legal", staff.DocumentsAudience), body)
		if w.Code != want {
			t.Fatalf("bundle %s %s: %d want %d", method, path, w.Code, want)
		}
		return w.Result()
	}
	content := assessmentFixture()
	definition := uuid()
	draft := assessmentDraftRequest{EventID: uuid(), DefinitionID: definition, Version: "assessment-1", Locale: "es", Content: content}
	result := send("POST", "/internal/assessments/drafts", author, draft, 200)
	var created map[string]string
	if json.NewDecoder(result.Body).Decode(&created) != nil {
		t.Fatal("assessment result invalid")
	}
	result.Body.Close()
	digest := content.Digest()
	hash := hex.EncodeToString(digest[:])
	if created["definition_id"] != definition || created["sha256"] != hash {
		t.Fatal("noncanonical draft hash")
	}
	send("POST", "/internal/assessments/drafts", author, draft, 200).Body.Close()
	canonical, _ := json.Marshal(content)
	// The exact same UUID and SHA exist in both physical tables. A typed route
	// must still reject the other resource, not grade by whichever table exists.
	if _, err := admin.Exec(`INSERT INTO legal_documents(id,kind,version,locale,content,material_change) VALUES($1,'privacy','shadow','es',$2,true)`, definition, string(canonical)); err != nil {
		t.Fatal(err)
	}
	wrong := map[string]any{"event_id": uuid(), "document_id": definition, "sha256": hash, "decision": "approved"}
	send("POST", "/internal/documents/reviews", reviewer, wrong, 409).Body.Close()
	send("GET", "/internal/documents/"+definition, reviewer, nil, 404).Body.Close()
	review := assessmentReviewRequest{assessmentCommand: assessmentCommand{EventID: uuid(), DefinitionID: definition, SHA256: hash}, Decision: "approved"}
	send("POST", "/internal/assessments/reviews", author, review, 403).Body.Close()
	publication := assessmentCommand{EventID: uuid(), DefinitionID: definition, SHA256: hash}
	send("POST", "/internal/assessments/publications", reviewer, publication, 409).Body.Close()
	send("POST", "/internal/assessments/reviews", reviewer, review, 200).Body.Close()
	send("POST", "/internal/assessments/reviews", reviewer, review, 200).Body.Close()
	send("POST", "/internal/assessments/publications", reviewer, publication, 200).Body.Close()
	send("POST", "/internal/assessments/publications", reviewer, publication, 200).Body.Close()
	var view map[string]any
	result = send("GET", "/internal/assessments/"+definition, reviewer, nil, 200)
	if json.NewDecoder(result.Body).Decode(&view) != nil || view["kind"] != "compa_assessment" || view["content"] != string(canonical) || view["sha256"] != hash {
		t.Fatal("exact private assessment not readable")
	}
	result.Body.Close()
	// Reading an assessment via a document route (or vice versa) never falls back.
	wrongQuiz := assessmentReviewRequest{assessmentCommand: assessmentCommand{EventID: uuid(), DefinitionID: docID, SHA256: bodyDraft()["sha256"].(string)}, Decision: "approved"}
	send("POST", "/internal/assessments/reviews", reviewer, wrongQuiz, 409).Body.Close()
	documents := []bundleDocument{{ID: docID, SHA256: bodyDraft()["sha256"].(string)}}
	for i, kind := range []string{"terms_client", "terms_compa", "community_rules", "safety_rules"} {
		id, event := uuid(), uuid()
		body := bodyDraft()
		body["event_id"] = event
		body["document_id"] = id
		body["kind"] = kind
		body["version"] = fmt.Sprintf("bundle-%d", i)
		send("POST", "/internal/documents/drafts", author, body, 200).Body.Close()
		send("POST", "/internal/documents/reviews", reviewer, map[string]any{"event_id": uuid(), "document_id": id, "sha256": body["sha256"], "decision": "approved"}, 200).Body.Close()
		send("POST", "/internal/documents/publications", reviewer, map[string]any{"event_id": uuid(), "document_id": id, "sha256": body["sha256"]}, 200).Body.Close()
		documents = append(documents, bundleDocument{ID: id, SHA256: body["sha256"].(string)})
	}
	expected := int64(0)
	bundle := bundleRequest{EventID: uuid(), Expected: &expected, Locale: "es", Documents: documents, Assessment: bundleAssessment{ID: definition, SHA256: hash}, Summary: []string{"Resumen sintético revisado."}}
	var auditBefore int
	if admin.QueryRow("SELECT count(*) FROM audit.log").Scan(&auditBefore) != nil {
		t.Fatal("audit fixture unavailable")
	}
	var probeBefore int
	if admin.QueryRow("SELECT last_value FROM editorial_fixture_probes").Scan(&probeBefore) != nil {
		t.Fatal("probe unavailable")
	}
	calls := 0
	s.now = func() time.Time {
		calls++
		if calls >= 3 {
			return time.Now().Add(6 * time.Minute)
		}
		return time.Now()
	}
	send("POST", "/internal/documents/activations", reviewer, bundle, 403).Body.Close()
	s.now = time.Now
	var head, bindings, audits, probe int
	if admin.QueryRow("SELECT version FROM documents.head WHERE locale='es'").Scan(&head) != nil || head != 0 {
		t.Fatal("expired bundle changed head")
	}
	if admin.QueryRow("SELECT count(*) FROM compa_attestation_requirements").Scan(&bindings) != nil || bindings != 0 {
		t.Fatal("expired bundle leaked quiz binding")
	}
	if admin.QueryRow("SELECT count(*) FROM audit.log").Scan(&audits) != nil || audits != auditBefore {
		t.Fatal("expired bundle committed audit")
	}
	if admin.QueryRow("SELECT last_value FROM editorial_fixture_probes").Scan(&probe) != nil || probe != probeBefore+1 {
		t.Fatal("bundle did not reach real audit insert")
	}
	result = send("POST", "/internal/documents/activations", reviewer, bundle, 200)
	var activated map[string]int64
	if json.NewDecoder(result.Body).Decode(&activated) != nil || activated["registry_version"] != 1 {
		t.Fatal("bundle result invalid")
	}
	result.Body.Close()
	// Set ordering is irrelevant, but actor/hash/summary/expected revision are not.
	sort.Slice(bundle.Documents, func(i, j int) bool { return bundle.Documents[i].ID < bundle.Documents[j].ID })
	send("POST", "/internal/documents/activations", reviewer, bundle, 200).Body.Close()
	send("POST", "/internal/documents/activations", author, bundle, 409).Body.Close()
	altered := bundle
	altered.EventID = uuid()
	send("POST", "/internal/documents/activations", reviewer, altered, 409).Body.Close()
	one := int64(1)
	second := bundle
	second.EventID = uuid()
	second.Expected = &one
	send("POST", "/internal/documents/activations", reviewer, second, 200).Body.Close()
	send("POST", "/internal/documents/activations", reviewer, bundle, 200).Body.Close()
	if admin.QueryRow("SELECT version FROM documents.head WHERE locale='es'").Scan(&head) != nil || head != 2 {
		t.Fatal("old bundle replay rewound head")
	}
	if admin.QueryRow("SELECT count(*) FROM compa_attestation_requirements WHERE definition_id=$1", definition).Scan(&bindings) != nil || bindings != 2 {
		t.Fatal("same reviewed assessment not reusable across registries")
	}
	// Competing CAS commands: exactly one new registry and quiz binding commit.
	two := int64(2)
	a, b := second, second
	a.Expected = &two
	b.Expected = &two
	a.EventID = uuid()
	b.EventID = uuid()
	var group sync.WaitGroup
	statuses := make(chan int, 2)
	for _, body := range []bundleRequest{a, b} {
		body := body
		group.Add(1)
		go func() {
			defer group.Done()
			w := request(t, handler, "POST", "/internal/documents/activations", token(reviewer, "legal", staff.DocumentsAudience), body)
			statuses <- w.Code
		}()
	}
	group.Wait()
	close(statuses)
	codes := []int{}
	for code := range statuses {
		codes = append(codes, code)
	}
	sort.Ints(codes)
	if len(codes) != 2 || codes[0] != 200 || codes[1] != 409 {
		t.Fatal("bundle CAS failed", codes)
	}
	if admin.QueryRow("SELECT count(*) FROM compa_attestation_requirements").Scan(&bindings) != nil || bindings != 3 {
		t.Fatal("partial or duplicate race binding")
	}
	// A raw operator activation is not retroactively adopted into this workflow.
	chain, service := uuid(), uuid()
	if _, err := admin.Exec(`INSERT INTO audit.chain_heads(chain_id) VALUES($1);`, chain); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(`INSERT INTO audit.writer_principals VALUES('postgres',$1,$2)`, service, chain); err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, d := range documents {
		ids = append(ids, d.ID)
	}
	rawEvent := uuid()
	if _, err := admin.Exec(`SELECT documents.activate($1,3,'es',$2::uuid[],$3,$4,$5::text[])`, rawEvent, pq.Array(ids), policy, reviewer, pq.Array(bundle.Summary)); err != nil {
		t.Fatal(err)
	}
	three := int64(3)
	retrofit := bundle
	retrofit.EventID = rawEvent
	retrofit.Expected = &three
	send("POST", "/internal/documents/activations", reviewer, retrofit, 409).Body.Close()
	if admin.QueryRow("SELECT count(*) FROM compa_attestation_requirements").Scan(&bindings) != nil || bindings != 3 {
		t.Fatal("raw activation retrofitted with non-atomic quiz")
	}
}

func TestAssessmentDraftDoesNotAcceptApprovalOrInvalidGrading(t *testing.T) {
	access, token := fixtureAccess(t)
	server := &Server{access: access, policy: policy, now: time.Now}
	handler := server.Handler()
	valid := assessmentDraftRequest{EventID: draftEvent, DefinitionID: docID, Version: "candidate-1", Locale: "es", Content: assessmentFixture()}
	for _, field := range []string{"actor", "approved_by", "policy_version", "sha256", "published_at"} {
		raw, _ := json.Marshal(valid)
		var body map[string]any
		json.Unmarshal(raw, &body)
		body[field] = reviewer
		w := request(t, handler, "POST", "/internal/assessments/drafts", token(author, "legal", staff.DocumentsAudience), body)
		if w.Code != 400 {
			t.Fatal("client asserted assessment approval/canonical hash", field, w.Code)
		}
	}
	invalid := valid
	invalid.Content = assessmentFixture()
	invalid.Content.Questions[0].CorrectOption = "not_an_option"
	w := request(t, handler, "POST", "/internal/assessments/drafts", token(author, "legal", staff.DocumentsAudience), invalid)
	if w.Code != 400 {
		t.Fatal("invalid grading reached storage", w.Code)
	}
	zero := int64(0)
	body := bundleRequest{EventID: draftEvent, Expected: &zero, Locale: "es", Assessment: bundleAssessment{ID: docID, SHA256: fmt.Sprintf("%064d", 1)}, Summary: []string{}}
	for i := 0; i < 5; i++ {
		body.Documents = append(body.Documents, bundleDocument{ID: fmt.Sprintf("aaaaaaaa-aaaa-4aaa-8aaa-%012d", i+1), SHA256: fmt.Sprintf("%064d", i+1)})
	}
	if !body.valid() {
		t.Fatal("valid bundle control rejected")
	}
	body.Documents[1] = body.Documents[0]
	w = request(t, handler, "POST", "/internal/documents/activations", token(author, "legal", staff.DocumentsAudience), body)
	if w.Code != 400 {
		t.Fatal("duplicate bundle target reached storage", w.Code)
	}
}
