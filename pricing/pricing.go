// Package pricing 是内置模型参考价的单一来源。
//
// 定价只能近似：各家价格随版本/渠道变动，这里给的是公开标价的数量级，用于
// 让用户看清“哪个任务、哪个 profile 在烧钱”的相对分布，不承诺账单精度。
// 前缀匹配、按声明顺序命中（specific 在前，free 在最前，避免 ":free" 被当付费）。
package pricing

import "strings"

type ModelPrice struct {
	Prefix string
	In     float64 // USD / 1M input tokens
	Out    float64 // USD / 1M output tokens
}

var modelPrices = []ModelPrice{
	{"free", 0, 0},
	{"claude-opus", 15, 75},
	{"claude-sonnet", 3, 15},
	{"claude-haiku", 0.8, 4},
	{"gpt-4o", 2.5, 10},
	{"gpt-4.1", 2, 8},
	{"gpt-5", 1.25, 10},
	{"o3", 2, 8},
	{"gemini-2.5-pro", 1.25, 10},
	{"gemini-2.5-flash", 0.3, 2.5},
	{"deepseek", 0.27, 1.1},
	{"glm", 0.6, 2},
	{"qwen", 0.4, 1.2},
	{"kimi", 0.6, 2.5},
	{"nemotron", 0, 0},
	{"llama", 0.2, 0.6},
}

// Estimate 返回按模型名估算的 USD 成本；known=false 表示模型不在定价表，
// 成本按 0 计且调用方需要把模型名上报给用户（不静默算错）。
func Estimate(model string, inTok, outTok int64) (usd float64, known bool) {
	m := strings.ToLower(model)
	for _, p := range modelPrices {
		if strings.Contains(m, p.Prefix) {
			return (float64(inTok)*p.In + float64(outTok)*p.Out) / 1e6, true
		}
	}
	return 0, false
}

// Table 返回内置价格的副本（评测报告展示用）。
func Table() []ModelPrice {
	out := make([]ModelPrice, len(modelPrices))
	copy(out, modelPrices)
	return out
}
