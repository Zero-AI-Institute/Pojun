package server

import (
	"errors"
	"log"
	"net/http"

	"github.com/chu0119/pojun/db"
)

// SRC/众测 program profile（v0.4.112）：任务级只读元数据 + 一个受控写入口。
//
//	GET /api/tasks/{id}/program-profile -> {task_id, profile|null}
//	PUT /api/tasks/{id}/program-profile  body=ProgramProfile（空对象=清除）
//
// profile 不是授权范围的替代品；它只影响提示、原生 HTTP 的 X-Bug-Bounty/RPS/
// dry-run。保存后 invalidateTaskAgents，让下一次 planner/worker 装配读到新值。

func (s *Server) getTaskProgramProfile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.m.Task(id); !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	profile, found, err := pg.GetTaskProgramProfile(id)
	if err != nil {
		log.Printf("[program] task %s 读取 profile 失败: %v", id, err)
		writeErr(w, http.StatusInternalServerError, "读取 program profile 失败")
		return
	}
	if !found {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"task_id": id, "profile": profile})
}

func (s *Server) putTaskProgramProfile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.m.Task(id); !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var profile db.ProgramProfile
	if err := decode(r, &profile); err != nil {
		writeErr(w, http.StatusBadRequest, "参数错误: "+err.Error())
		return
	}
	if err := profile.Normalize(); err != nil {
		writeErr(w, http.StatusBadRequest, "program profile 非法: "+err.Error())
		return
	}
	if err := pg.SaveTaskProgramProfile(id, &profile); err != nil {
		if errors.Is(err, db.ErrTaskNotFound) {
			writeErr(w, http.StatusNotFound, "task not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "保存 program profile 失败")
		return
	}
	// 下一次 agent 装配重新读 profile；正在跑的 run 不改（与任务设置变更语义一致）。
	s.invalidateTaskAgents()
	log.Printf("[program] task %s profile 已更新（platform=%q handle=%q rps=%.2f dry_run=%v）",
		id, profile.Platform, profile.Handle, profile.RPS, profile.DryRun)
	// 空 profile 归一为 null，前端可以直接把返回当当前值。
	if profile.IsZero() {
		writeJSON(w, http.StatusOK, map[string]any{"task_id": id, "profile": nil})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"task_id": id, "profile": &profile})
}
