package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTaskProgramProfileHandlers(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}
	task, err := m.CreateTask("program profile handler", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })

	get := func(id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/tasks/"+id+"/program-profile", nil)
		req.SetPathValue("id", id)
		rec := httptest.NewRecorder()
		s.getTaskProgramProfile(rec, req)
		return rec
	}
	put := func(id, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/api/tasks/"+id+"/program-profile", bytes.NewBufferString(body))
		req.SetPathValue("id", id)
		rec := httptest.NewRecorder()
		s.putTaskProgramProfile(rec, req)
		return rec
	}

	if rec := get("999999999"); rec.Code != http.StatusNotFound {
		t.Fatalf("missing task = %d %s", rec.Code, rec.Body.String())
	}
	if rec := get(task.ID); rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"profile":null`)) {
		t.Fatalf("initial get = %d %s", rec.Code, rec.Body.String())
	}
	body := `{"platform":"HackerOne","handle":"acme","scope":["example.com"],"excluded":["admin.example.com"],"rps":2.5,"dry_run":true}`
	if rec := put(task.ID, body); rec.Code != http.StatusOK {
		t.Fatalf("put = %d %s", rec.Code, rec.Body.String())
	}
	rec := get(task.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("get after put = %d %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Profile *struct {
			Platform string  `json:"platform"`
			Handle   string  `json:"handle"`
			RPS      float64 `json:"rps"`
			DryRun   bool    `json:"dry_run"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Profile == nil || payload.Profile.Platform != "hackerone" || payload.Profile.Handle != "acme" || payload.Profile.RPS != 2.5 || !payload.Profile.DryRun {
		t.Fatalf("profile payload = %s", rec.Body.String())
	}
	// 非法 RPS -> 400；空对象 -> 清除。
	if rec := put(task.ID, `{"rps":999}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad rps = %d %s", rec.Code, rec.Body.String())
	}
	if rec := put(task.ID, `{}`); rec.Code != http.StatusOK {
		t.Fatalf("clear = %d %s", rec.Code, rec.Body.String())
	}
	if rec := get(task.ID); !bytes.Contains(rec.Body.Bytes(), []byte(`"profile":null`)) {
		t.Fatalf("after clear = %s", rec.Body.String())
	}
}
