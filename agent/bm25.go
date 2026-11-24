package agent

// 轻量 BM25（P2-2）：用于工具 schema 预算下的「按任务意图选可见工具」，
// 不引入外部依赖。中文按字 + 二元组切分，英文/数字按词切分。

import (
	"math"
	"sort"
	"strings"
	"unicode"
)

type bm25Doc struct {
	name   string
	text   string
	tf     map[string]int
	length int
}

type bm25Index struct {
	docs []bm25Doc
	df   map[string]int
	avg  float64
}

func newBM25Index(names, texts []string) *bm25Index {
	if len(names) != len(texts) {
		return &bm25Index{df: map[string]int{}}
	}
	idx := &bm25Index{df: map[string]int{}}
	total := 0
	for i, name := range names {
		tokens := tokenizeBM25(name + " " + texts[i])
		tf := make(map[string]int, len(tokens))
		for _, t := range tokens {
			tf[t]++
		}
		seen := make(map[string]bool, len(tf))
		for t := range tf {
			if !seen[t] {
				idx.df[t]++
				seen[t] = true
			}
		}
		idx.docs = append(idx.docs, bm25Doc{name: name, text: texts[i], tf: tf, length: len(tokens)})
		total += len(tokens)
	}
	if len(idx.docs) > 0 {
		idx.avg = float64(total) / float64(len(idx.docs))
	}
	return idx
}

// search returns tool names ordered by BM25 score (desc). Empty query returns nil.
func (idx *bm25Index) search(query string, k int) []string {
	if idx == nil || k <= 0 {
		return nil
	}
	q := tokenizeBM25(query)
	if len(q) == 0 {
		return nil
	}
	const k1, b = 1.5, 0.75
	type hit struct {
		name  string
		score float64
	}
	hits := make([]hit, 0, len(idx.docs))
	n := float64(len(idx.docs))
	for _, d := range idx.docs {
		var score float64
		for _, term := range q {
			tf := float64(d.tf[term])
			if tf == 0 {
				continue
			}
			df := float64(idx.df[term])
			idf := math.Log(1 + (n-df+0.5)/(df+0.5))
			denom := tf + k1*(1-b+b*float64(d.length)/math.Max(idx.avg, 1))
			score += idf * tf * (k1 + 1) / denom
		}
		if score > 0 {
			hits = append(hits, hit{name: d.name, score: score})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].score > hits[j].score })
	if len(hits) > k {
		hits = hits[:k]
	}
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.name)
	}
	return out
}

// tokenizeBM25 lowercases and emits ASCII words plus Han runes/bigrams.
func tokenizeBM25(s string) []string {
	s = strings.ToLower(s)
	var out []string
	var word []rune
	var han []rune
	flushWord := func() {
		if len(word) > 0 {
			out = append(out, string(word))
			word = word[:0]
		}
	}
	flushHan := func() {
		for i, r := range han {
			out = append(out, string(r))
			if i+1 < len(han) {
				out = append(out, string(han[i:i+2]))
			}
		}
		han = han[:0]
	}
	for _, r := range s {
		switch {
		case unicode.Is(unicode.Han, r):
			flushWord()
			han = append(han, r)
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			flushHan()
			word = append(word, r)
		default:
			flushWord()
			flushHan()
		}
	}
	flushWord()
	flushHan()
	return out
}
