package attestations

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func fixture() (Definition, Submission, time.Time) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	d := Definition{Version: "synthetic-1", Locale: "es", RegistryVersion: 3,
		PolicyVersion: "11111111-1111-4111-8111-111111111111", Approved: true,
		ApprovedBy: "22222222-2222-4222-8222-222222222222", ReviewedAt: now.Add(-time.Hour), PublishedAt: now.Add(-time.Minute)}
	for _, id := range []string{"no_illicit_substances", "no_sexual_services", "catalog_only", "adults_only", "enforcement_and_appeal"} {
		d.Content.Statements = append(d.Content.Statements, Statement{ID: id, Text: "Declaración sintética para pruebas; no texto aprobado para usuarios."})
	}
	for _, id := range []string{"scenario_one", "scenario_two", "scenario_three"} {
		d.Content.Questions = append(d.Content.Questions, Question{ID: id, Text: "Escenario sintético", Options: []Option{{ID: "reject_report", Text: "Opción sintética correcta"}, {ID: "proceed", Text: "Opción sintética incorrecta"}}, CorrectOption: "reject_report"})
	}
	d.SHA256 = d.Content.Digest()
	input := Submission{Version: d.Version, SHA256: d.SHA256, Statements: map[string]bool{}, Answers: map[string]string{}}
	for _, s := range d.Content.Statements {
		input.Statements[s.ID] = true
	}
	for _, q := range d.Content.Questions {
		input.Answers[q.ID] = q.CorrectOption
	}
	return d, input, now
}
func TestExplicitDeclarationsAndThreeQuestions(t *testing.T) {
	d, input, now := fixture()
	result, err := Evaluate(d, input, now)
	if err != nil || result.Version != d.Version || result.SHA256 != d.SHA256 || !result.PassedAt.Equal(now) || result.PolicyVersion != d.PolicyVersion {
		t.Fatal(result, err)
	}
	for _, statement := range d.Content.Statements {
		t.Run(statement.ID, func(t *testing.T) {
			_, input, _ := fixture()
			input.Statements[statement.ID] = false
			if _, err := Evaluate(d, input, now); !errors.Is(err, ErrDeclarations) {
				t.Fatal(err)
			}
			delete(input.Statements, statement.ID)
			if _, err := Evaluate(d, input, now); !errors.Is(err, ErrDeclarations) {
				t.Fatal(err)
			}
		})
	}
	for _, q := range d.Content.Questions {
		t.Run(q.ID, func(t *testing.T) {
			_, input, _ := fixture()
			input.Answers[q.ID] = "proceed"
			if _, err := Evaluate(d, input, now); !errors.Is(err, ErrQuiz) {
				t.Fatal(err)
			}
			delete(input.Answers, q.ID)
			if _, err := Evaluate(d, input, now); !errors.Is(err, ErrQuiz) {
				t.Fatal(err)
			}
		})
	}
	input.Statements["unreviewed_extra"] = true
	if _, err := Evaluate(d, input, now); !errors.Is(err, ErrDeclarations) {
		t.Fatal(err)
	}
	_, input, _ = fixture()
	input.Answers["extra"] = "reject_report"
	if _, err := Evaluate(d, input, now); !errors.Is(err, ErrQuiz) {
		t.Fatal(err)
	}
}
func TestUnreviewedChangedAndMalformedDefinitionsNeverPass(t *testing.T) {
	mutations := map[string]func(*Definition){
		"pending":                   func(d *Definition) { d.Approved = false },
		"missing_reviewer":          func(d *Definition) { d.ApprovedBy = "" },
		"future_publication":        func(d *Definition) { d.PublishedAt = d.PublishedAt.Add(24 * time.Hour) },
		"publication_before_review": func(d *Definition) { d.PublishedAt = d.ReviewedAt.Add(-time.Second) },
		"changed_content":           func(d *Definition) { d.Content.Statements[0].Text = "Otra declaración" },
		"duplicate_statement":       func(d *Definition) { d.Content.Statements[1] = d.Content.Statements[0]; d.SHA256 = d.Content.Digest() },
		"unreviewed_statement_kind": func(d *Definition) { d.Content.Statements[0].ID = "other"; d.SHA256 = d.Content.Digest() },
		"only_two_questions":        func(d *Definition) { d.Content.Questions = d.Content.Questions[:2]; d.SHA256 = d.Content.Digest() },
		"duplicate_question":        func(d *Definition) { d.Content.Questions[1] = d.Content.Questions[0]; d.SHA256 = d.Content.Digest() },
		"duplicate_option": func(d *Definition) {
			d.Content.Questions[0].Options[1] = d.Content.Questions[0].Options[0]
			d.SHA256 = d.Content.Digest()
		},
		"nonexistent_answer": func(d *Definition) { d.Content.Questions[0].CorrectOption = "absent"; d.SHA256 = d.Content.Digest() },
		"missing_registry":   func(d *Definition) { d.RegistryVersion = 0 },
		"missing_policy":     func(d *Definition) { d.PolicyVersion = "" },
		"oversized_text": func(d *Definition) {
			d.Content.Statements[0].Text = strings.Repeat("a", 2001)
			d.SHA256 = d.Content.Digest()
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			d, input, now := fixture()
			mutate(&d)
			if _, err := Evaluate(d, input, now); !errors.Is(err, ErrUnavailable) {
				t.Fatal(err)
			}
		})
	}
	d, input, now := fixture()
	input.Version = "synthetic-older"
	if _, err := Evaluate(d, input, now); !errors.Is(err, ErrChanged) {
		t.Fatal(err)
	}
	_, input, _ = fixture()
	input.SHA256 = [32]byte{}
	if _, err := Evaluate(d, input, now); !errors.Is(err, ErrChanged) {
		t.Fatal(err)
	}
}
func TestPublicAssessmentOmitsAnswerKeyAndDoesNotAliasDefinition(t *testing.T) {
	d, _, now := fixture()
	view, err := d.Public(now)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(view)
	if strings.Contains(string(raw), "correct_option") {
		t.Fatal("answer key exposed")
	}
	view.Statements[0].Text = "Changed client text"
	view.Questions[0].Options[0].Text = "Changed client option"
	if err := d.Validate(now); err != nil {
		t.Fatal("public view mutated authoritative definition", err)
	}
}
