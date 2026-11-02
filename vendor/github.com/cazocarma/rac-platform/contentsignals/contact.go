package contentsignals

import (
	"regexp"
	"strings"
)

// Contact rules are public and deterministic: they can be exported to the
// app for a pre-send warning, while the backend always revalidates.
const (
	RuleContactPhone     = "contact.phone"
	RuleContactEmail     = "contact.email"
	RuleContactURL       = "contact.url"
	RuleContactHandle    = "contact.handle"
	RuleContactMessenger = "contact.messenger"
)

var digitWords = map[string]rune{
	"cero": '0', "uno": '1', "una": '1', "dos": '2', "tres": '3', "cuatro": '4',
	"cinco": '5', "seis": '6', "siete": '7', "ocho": '8', "nueve": '9',
}

// Messaging and social apps people use to move a conversation off RAC.
// Ambiguous English words ("line", "signal") are deliberately absent.
var messengers = map[string]bool{
	"wsp": true, "wasap": true, "wasa": true, "whatsapp": true, "whatsap": true, "watsap": true, "wpp": true, "guasap": true,
	"ig": true, "insta": true, "instagram": true, "telegram": true, "tg": true,
	"snap": true, "snapchat": true, "tiktok": true, "facebook": true, "fb": true, "messenger": true,
	"discord": true, "onlyfans": true, "kik": true,
}

var (
	emailPattern  = regexp.MustCompile(`[a-z0-9][a-z0-9._%+-]*@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}`)
	urlPattern    = regexp.MustCompile(`(https?://|www\.)[^\s]+|\bt\.me/[a-z0-9_]+|\b[a-z0-9-]{2,}\.(com|cl|net|org|io|me|app|ly|gl|co|info|xyz|link|site|online|store|shop)\b`)
	handlePattern = regexp.MustCompile(`(^|[^a-z0-9._@])@[a-z0-9._]{3,30}`)
	digitsPattern = regexp.MustCompile(`\+?\d+`)
	wordPattern   = regexp.MustCompile(`[a-z]+`)
	// Chile: 9 national digits (mobile 9XXXXXXXX, landline area+number),
	// optionally preceded by the 56 country code.
	phonePattern = regexp.MustCompile(`^(56)?[2-9]\d{8}$`)
)

// compact rewrites a contact view so obfuscated contacts become literal:
// digit words become digits, "arroba"/"punto" become "@"/".", and the
// separators inside a digit run or an address disappear. Offsets still map
// every rune to the original text.
func compact(v view) view {
	// '/' stays inside tokens so "https://x.cl/y" and "t.me/user" survive.
	split := func(r rune) bool {
		return (isSeparator(r) && r != '/') || r == '(' || r == ')' || r == '[' || r == ']'
	}
	type token struct {
		text       []rune
		start, end int
		kind       byte // 'd' digit run, 'p' address punctuation, 'w' word
	}
	tokens := []token{}
	for i := 0; i < len(v.text); {
		if split(v.text[i]) {
			i++
			continue
		}
		j := i
		for j < len(v.text) && !split(v.text[j]) {
			j++
		}
		word := string(v.text[i:j])
		t := token{text: []rune(word), start: i, end: j, kind: 'w'}
		if d, ok := digitWords[word]; ok {
			t.text, t.kind = []rune{d}, 'd'
		} else if word == "arroba" || word == "at" {
			t.text, t.kind = []rune{'@'}, 'p'
		} else if word == "punto" || word == "dot" {
			t.text, t.kind = []rune{'.'}, 'p'
		} else if strings.Trim(word, "+0123456789") == "" {
			t.kind = 'd'
		}
		tokens = append(tokens, t)
		i = j
	}
	var out view
	for k, t := range tokens {
		joined := k > 0 && (t.kind == 'p' || tokens[k-1].kind == 'p' || (t.kind == 'd' && tokens[k-1].kind == 'd') ||
			// Keep dotted addresses written with real dots ("juan.perez@x.cl").
			(t.start > 0 && v.text[t.start-1] == '.' && tokens[k-1].end == t.start-1))
		if k > 0 && !joined {
			out.add(' ', v.offsets[t.start], v.offsets[t.start])
		}
		if k > 0 && joined && tokens[k-1].kind == 'w' && t.kind == 'w' {
			out.add('.', v.offsets[t.start-1], v.ends[t.start-1])
		}
		for _, r := range t.text {
			out.add(r, v.offsets[t.start], v.ends[t.end-1])
		}
	}
	return out
}

// detectContact returns contact matches with spans over the original text.
func detectContact(input string) []Signal {
	v := compact(contactView(input))
	text := string(v.text)
	// Byte offsets in text → rune indices in v.
	runeAt := make([]int, len(text)+1)
	count := 0
	for i := range text {
		runeAt[i] = count
		count++
	}
	runeAt[len(text)] = count
	signals := []Signal{}
	add := func(rule string, from, to int) {
		a, b := runeAt[from], runeAt[to]
		if b > a {
			signals = append(signals, Signal{Category: CategoryContact, RuleID: rule, Score: 1, Spans: []Span{v.span(a, b)}})
		}
	}
	for _, m := range emailPattern.FindAllStringIndex(text, -1) {
		add(RuleContactEmail, m[0], m[1])
	}
	for _, m := range urlPattern.FindAllStringIndex(text, -1) {
		if !strings.Contains(text[m[0]:m[1]], "@") {
			add(RuleContactURL, m[0], m[1])
		}
	}
	for _, m := range handlePattern.FindAllStringIndex(text, -1) {
		start := m[0]
		if text[start] != '@' {
			start++
		}
		add(RuleContactHandle, start, m[1])
	}
	for _, m := range digitsPattern.FindAllStringIndex(text, -1) {
		if phonePattern.MatchString(strings.TrimPrefix(text[m[0]:m[1]], "+")) {
			add(RuleContactPhone, m[0], m[1])
		}
	}
	for _, m := range wordPattern.FindAllStringIndex(text, -1) {
		if messengers[text[m[0]:m[1]]] {
			add(RuleContactMessenger, m[0], m[1])
		}
	}
	return signals
}
