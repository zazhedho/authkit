package shared

import (
	"encoding/json"
	"html"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/google/uuid"
)

// The helpers in this file are stdlib-only copies of the gokit string helpers
// the services used, so services need no framework package. Output matches
// gokit v0.2.1; text_test.go pins it.

var (
	htmlScript = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	htmlStyle  = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	htmlTag    = regexp.MustCompile(`<[^>]*>`)
)

// NewID returns a UUID v7 string, falling back to v4 if v7 cannot be made.
// It is the default for the services' injected NewID.
func NewID() string {
	if id, err := uuid.NewV7(); err == nil {
		return id.String()
	}
	return uuid.NewString()
}

// NormalizeKey trims and lower-cases value.
func NormalizeKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// StripHTML removes script and style blocks and tags, unescapes entities and
// collapses whitespace.
func StripHTML(s string) string {
	s = htmlScript.ReplaceAllString(s, " ")
	s = htmlStyle.ReplaceAllString(s, " ")
	s = htmlTag.ReplaceAllString(s, " ")
	return strings.Join(strings.Fields(html.UnescapeString(s)), " ")
}

// HumanizeKey turns snake_case and kebab-case keys into space separated words.
func HumanizeKey(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return value
	}

	value = strings.ReplaceAll(value, "_", " ")
	value = strings.ReplaceAll(value, "-", " ")
	return strings.Join(strings.Fields(value), " ")
}

// TitleHumanized is HumanizeKey with each word capitalised.
func TitleHumanized(value string) string {
	value = HumanizeKey(value)
	if value == "" {
		return value
	}

	words := strings.Fields(value)
	for i, word := range words {
		if word == "" {
			continue
		}
		words[i] = strings.ToUpper(word[:1]) + strings.ToLower(word[1:])
	}
	return strings.Join(words, " ")
}

// JsonEncode marshals data, returning "" when it cannot be encoded.
func JsonEncode(data any) string {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	return string(jsonData)
}

// InterfaceString renders strings and byte slices as is and other values as
// JSON.
func InterfaceString(data any) string {
	if data == nil {
		return ""
	}
	switch v := data.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		bytes, _ := json.Marshal(data)
		return string(bytes)
	}
}

// NormalizeUUIDPointer returns the trimmed value when it is a UUID, else nil.
func NormalizeUUIDPointer(input string) *string {
	value := strings.TrimSpace(input)
	if value == "" {
		return nil
	}

	if _, err := uuid.Parse(value); err != nil {
		return nil
	}

	return &value
}

// NormalizePayload round-trips input through JSON so structs become maps and
// slices; nil becomes an empty map and unencodable input is returned as is.
func NormalizePayload(input any) any {
	if input == nil {
		return map[string]any{}
	}

	raw, err := json.Marshal(input)
	if err != nil {
		return input
	}

	var normalized any
	if err := json.Unmarshal(raw, &normalized); err != nil {
		return input
	}

	return normalized
}

// IsSensitiveKey reports whether a payload key names a secret.
func IsSensitiveKey(key string) bool {
	k := NormalizeKey(key)
	return strings.Contains(k, "password") ||
		strings.Contains(k, "token") ||
		strings.Contains(k, "secret") ||
		strings.Contains(k, "otp")
}

// RedactSensitivePayload normalises input and replaces the values of
// sensitive keys with "[REDACTED]".
func RedactSensitivePayload(input any) any {
	return RedactSensitiveValue(NormalizePayload(input))
}

// RedactSensitiveValue redacts sensitive keys in an already normalised value.
func RedactSensitiveValue(input any) any {
	switch v := input.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, val := range v {
			if IsSensitiveKey(k) {
				out[k] = "[REDACTED]"
				continue
			}
			out[k] = RedactSensitiveValue(val)
		}
		return out
	case []any:
		out := make([]any, 0, len(v))
		for _, val := range v {
			out = append(out, RedactSensitiveValue(val))
		}
		return out
	default:
		return v
	}
}

// TitleCase capitalises the first cased letter of each word and lower-cases
// the rest, with the word boundaries of golang.org/x/text/cases for English
// (an apostrophe, period or colon between letters stays inside the word).
func TitleCase(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	runes := []rune(s)
	midWord := false
	prevMid := false
	for i, r := range runes {
		if prevMid && isMidChar(r) {
			midWord = false
		}
		switch {
		case isCased(r):
			if midWord {
				b.WriteString(lowerRune(runes, i))
			} else {
				b.WriteString(titleRune(r))
				midWord = true
			}
		default:
			b.WriteRune(r)
			if isWordBreak(r) {
				midWord = false
			}
		}
		prevMid = isMidChar(r)
	}
	return b.String()
}

func isCased(r rune) bool {
	return unicode.IsUpper(r) || unicode.IsLower(r) || unicode.IsTitle(r) ||
		unicode.Is(unicode.Other_Lowercase, r) || unicode.Is(unicode.Other_Uppercase, r)
}

// isMidChar is the Unicode Word_Break classes MidLetter, MidNumLet and
// Single_Quote.
func isMidChar(r rune) bool {
	switch r {
	case '\'', '.', ':', '\u00b7', '\u0387', '\u055f', '\u05f4', '\u2018', '\u2019', '\u2024', '\u2027',
		'\ufe13', '\ufe52', '\ufe55', '\uff07', '\uff0e', '\uff1a':
		return true
	}
	return false
}

func isCaseIgnorable(r rune) bool {
	return isMidChar(r) || unicode.In(r, unicode.Mn, unicode.Me, unicode.Cf, unicode.Lm, unicode.Sk)
}

// isWordBreak reports whether r ends the current word, following the Unicode
// word-break classes: letters, digits, marks and connectors continue a word,
// scripts without ALetter segmentation (Han, Kana, Thai, ...) end it.
func isWordBreak(r rune) bool {
	return wordBreakBase(r) != inRanges(r, wordBreakExceptions)
}

func wordBreakBase(r rune) bool {
	switch {
	case isMidChar(r):
		return false
	case isKana(r):
		return true
	case unicode.IsLetter(r):
		return unicode.In(r, unicode.Han, unicode.Hiragana, unicode.Thai, unicode.Lao, unicode.Khmer, unicode.Myanmar)
	case unicode.Is(unicode.Nd, r), unicode.In(r, unicode.M, unicode.Cf, unicode.Pc), r == '\u202f', r == '\u066b', r == '\u05f3':
		return false
	}
	return true
}

// isKana covers the Word_Break=Katakana runes that Go's script tables class
// as Common, such as the prolonged sound marks.
func isKana(r rune) bool {
	return r >= 0x3031 && r <= 0x3035 || r == 0x309b || r == 0x309c ||
		r >= 0x30a0 && r <= 0x30fa || r >= 0x30fc && r <= 0x30ff || r >= 0x31f0 && r <= 0x31ff ||
		r >= 0x32d0 && r <= 0x32fe || r >= 0x3300 && r <= 0x3357 || r >= 0xff66 && r <= 0xff9d
}

func titleRune(r rune) string {
	if special, ok := titleSpecial[r]; ok {
		return special
	}
	return string(unicode.ToTitle(r))
}

// titleSpecial holds the word-initial mappings that differ from
// unicode.ToTitle: the unconditional entries of Unicode SpecialCasing, which
// expand to several runes.
var titleSpecial = map[rune]string{
	0x00df: "Ss",
	0x0149: "\u02bcN",
	0x01f0: "J\u030c",
	0x0390: "\u0399\u0308\u0301",
	0x03b0: "\u03a5\u0308\u0301",
	0x0587: "\u0535\u0582",
	0x1e96: "H\u0331",
	0x1e97: "T\u0308",
	0x1e98: "W\u030a",
	0x1e99: "Y\u030a",
	0x1e9a: "A\u02be",
	0x1f50: "\u03a5\u0313",
	0x1f52: "\u03a5\u0313\u0300",
	0x1f54: "\u03a5\u0313\u0301",
	0x1f56: "\u03a5\u0313\u0342",
	0x1fb2: "\u1fba\u0345",
	0x1fb4: "\u0386\u0345",
	0x1fb6: "\u0391\u0342",
	0x1fb7: "\u0391\u0342\u0345",
	0x1fc2: "\u1fca\u0345",
	0x1fc4: "\u0389\u0345",
	0x1fc6: "\u0397\u0342",
	0x1fc7: "\u0397\u0342\u0345",
	0x1fd2: "\u0399\u0308\u0300",
	0x1fd3: "\u0399\u0308\u0301",
	0x1fd6: "\u0399\u0342",
	0x1fd7: "\u0399\u0308\u0342",
	0x1fe2: "\u03a5\u0308\u0300",
	0x1fe3: "\u03a5\u0308\u0301",
	0x1fe4: "\u03a1\u0313",
	0x1fe6: "\u03a5\u0342",
	0x1fe7: "\u03a5\u0308\u0342",
	0x1ff2: "\u1ffa\u0345",
	0x1ff4: "\u038f\u0345",
	0x1ff6: "\u03a9\u0342",
	0x1ff7: "\u03a9\u0342\u0345",
	0xfb00: "Ff",
	0xfb01: "Fi",
	0xfb02: "Fl",
	0xfb03: "Ffi",
	0xfb04: "Ffl",
	0xfb05: "St",
	0xfb06: "St",
	0xfb13: "\u0544\u0576",
	0xfb14: "\u0544\u0565",
	0xfb15: "\u0544\u056b",
	0xfb16: "\u054e\u0576",
	0xfb17: "\u0544\u056d",
}

func lowerRune(runes []rune, i int) string {
	switch runes[i] {
	case '\u0130': // İ lowers to i plus a combining dot
		return "i\u0307"
	case '\u03a3': // Σ is ς at the end of a word
		if !nextCased(runes, i+1) {
			return "\u03c2"
		}
	}
	return string(unicode.ToLower(runes[i]))
}

func nextCased(runes []rune, from int) bool {
	for _, r := range runes[from:] {
		if isCaseIgnorable(r) {
			continue
		}
		return isCased(r)
	}
	return false
}

func inRanges(r rune, ranges [][2]rune) bool {
	i := sort.Search(len(ranges), func(i int) bool { return ranges[i][1] >= r })
	return i < len(ranges) && ranges[i][0] <= r
}

// wordBreakExceptions lists runes whose break result is flipped to match
// golang.org/x/text/cases v0.44.0: modifier symbols, numerals and historic
// scripts that Go's tables class differently.
var wordBreakExceptions = [][2]rune{
	{0x00b8, 0x00b8}, {0x02c2, 0x02c5}, {0x02d2, 0x02d7}, {0x02de, 0x02df},
	{0x02e5, 0x02eb}, {0x02ed, 0x02ed}, {0x02ef, 0x02ff}, {0x055a, 0x055c},
	{0x055e, 0x055e}, {0x058a, 0x058a}, {0x16ee, 0x16f0}, {0x1950, 0x196d},
	{0x1970, 0x1974}, {0x1980, 0x19ab}, {0x19b0, 0x19c9}, {0x19da, 0x19da},
	{0x1a20, 0x1a54}, {0x1aa7, 0x1aa7}, {0x200b, 0x200b}, {0x2180, 0x2182},
	{0x2185, 0x2188}, {0x3005, 0x3006}, {0x303b, 0x303b}, {0xa6e6, 0xa6ef},
	{0xa708, 0xa716}, {0xa720, 0xa721}, {0xa789, 0xa78a}, {0xaa80, 0xaaaf},
	{0xaab1, 0xaab1}, {0xaab5, 0xaab6}, {0xaab9, 0xaabd}, {0xaac0, 0xaac0},
	{0xaac2, 0xaac2}, {0xaadb, 0xaadd}, {0xab5b, 0xab5b}, {0x10140, 0x10174},
	{0x10341, 0x10341}, {0x1034a, 0x1034a}, {0x103d1, 0x103d5}, {0x11700, 0x1171a},
	{0x11740, 0x11746}, {0x12400, 0x1246e}, {0x16fe3, 0x16fe3}, {0x17000, 0x18cd5},
	{0x18cff, 0x18d1e}, {0x18d80, 0x18df2}, {0x1aff0, 0x1aff3}, {0x1aff5, 0x1affb},
	{0x1affd, 0x1affe}, {0x1b000, 0x1b000}, {0x1b120, 0x1b122}, {0x1b155, 0x1b155},
	{0x1b164, 0x1b167}, {0x1b170, 0x1b2fb}, {0x1f3fb, 0x1f3ff},
}
