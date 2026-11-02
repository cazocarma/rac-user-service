package contentsignals

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// MaxInput bounds analysis cost; longer texts are rejected, never truncated
// silently into a pass.
const MaxInput = 8192

// view is a normalized rendering of the original text. offsets[i] is the
// UTF-8 byte offset in the original where the rune text[i] came from, so
// matches map back to spans over the input the person wrote.
type view struct {
	text    []rune
	offsets []int
	ends    []int
}

func (v *view) add(r rune, start, end int) {
	v.text = append(v.text, r)
	v.offsets = append(v.offsets, start)
	v.ends = append(v.ends, end)
}

// span maps a [from,to) rune range of the view to original byte offsets.
func (v view) span(from, to int) Span {
	return Span{Start: v.offsets[from], End: v.ends[to-1]}
}

// Confusable letters that render as Latin. Only unambiguous lowercase forms
// are mapped; this is not a general transliteration table.
var homoglyphs = map[rune]rune{
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'к': 'k', 'м': 'm', 'т': 't', 'н': 'h', 'в': 'b',
	'α': 'a', 'ο': 'o', 'ρ': 'p', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ѵ': 'v',
}

// Leetspeak substitutions apply only to the lexicon view: the contact view
// keeps digits and '@' so numbers and addresses stay intact.
var leet = map[rune]rune{'4': 'a', '3': 'e', '1': 'i', '0': 'o', '5': 's', '7': 't', '@': 'a', '$': 's'}

// fold applies NFKC, lowercase, diacritic removal and homoglyph mapping to
// one original rune. It may yield zero runes (combining marks) or several.
func fold(r rune) []rune {
	out := []rune{}
	for _, c := range norm.NFD.String(norm.NFKC.String(string(r))) {
		if unicode.Is(unicode.Mn, c) {
			continue
		}
		c = unicode.ToLower(c)
		if mapped, ok := homoglyphs[c]; ok {
			c = mapped
		}
		out = append(out, c)
	}
	return out
}

func isSeparator(r rune) bool {
	return r == '.' || r == '-' || r == '_' || r == '*' || r == '·' || r == '|' || r == '/' || r == '\\' ||
		unicode.IsSpace(r) || unicode.Is(unicode.So, r) || unicode.Is(unicode.Sk, r)
}

// contactView keeps digits, '@', '+' and separators so contact patterns can
// be matched with their obfuscations.
func contactView(input string) view {
	var v view
	for start, r := range input {
		end := start + utf8.RuneLen(r)
		if r == utf8.RuneError {
			end = start + 1
		}
		for _, c := range fold(r) {
			v.add(c, start, end)
		}
	}
	return v
}

// lexiconView applies leetspeak, keeps letters only as word characters,
// collapses repeated letters and joins runs of single letters split by
// separators ("m.e.r.c.a", "m e r c a"). Runs shorter than three letters are
// not joined, so ordinary short words stay apart.
func lexiconView(input string) view {
	base := contactView(input)
	var letters view
	for i, c := range base.text {
		if mapped, ok := leet[c]; ok {
			c = mapped
		}
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			// Collapse repeats: "merrrrca" and "merca" share a form.
			if n := len(letters.text); n > 0 && letters.text[n-1] == c {
				letters.ends[n-1] = base.ends[i]
				continue
			}
			letters.add(c, base.offsets[i], base.ends[i])
			continue
		}
		if n := len(letters.text); n == 0 || letters.text[n-1] != ' ' {
			letters.add(' ', base.offsets[i], base.ends[i])
		}
	}
	return joinSpelledOut(letters)
}

func joinSpelledOut(v view) view {
	words := splitWords(v)
	var out view
	for i := 0; i < len(words); {
		j := i
		for j < len(words) && words[j][1]-words[j][0] == 1 {
			j++
		}
		if j-i >= 3 {
			// A spelled-out run becomes one word.
			if len(out.text) > 0 {
				out.add(' ', v.offsets[words[i][0]], v.offsets[words[i][0]])
			}
			for k := i; k < j; k++ {
				out.add(v.text[words[k][0]], v.offsets[words[k][0]], v.ends[words[k][0]])
			}
			i = j
			continue
		}
		if len(out.text) > 0 {
			out.add(' ', v.offsets[words[i][0]], v.offsets[words[i][0]])
		}
		for k := words[i][0]; k < words[i][1]; k++ {
			out.add(v.text[k], v.offsets[k], v.ends[k])
		}
		i++
	}
	return out
}

// splitWords returns [start,end) rune ranges of space-separated words.
func splitWords(v view) [][2]int {
	words := [][2]int{}
	start := -1
	for i, c := range v.text {
		if c == ' ' {
			if start >= 0 {
				words = append(words, [2]int{start, i})
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		words = append(words, [2]int{start, len(v.text)})
	}
	return words
}

// normalizeTerm puts a lexicon term in the same form as lexiconView output.
func normalizeTerm(term string) string {
	return strings.TrimSpace(string(lexiconView(term).text))
}
