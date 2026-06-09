package app

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
)

// editorMode is a small state machine for keystroke routing.
type editorMode int

const (
	modeNormal editorMode = iota
	modeInsert
	modeConfirmSave
	modeConfirmDelete
	modeConfirmDirty // prompted when Esc is pressed in INSERT with unsaved changes
)

type editorModel struct {
	bucket   string
	ta       textarea.Model
	mode     editorMode
	original string // policy as fetched from the server
	loaded   bool
	noPolicy bool // bucket has no policy yet
	err      string
	info     string

	findings []Finding

	width  int
	height int
}

func newEditorModel(bucket string) editorModel {
	ta := textarea.New()
	ta.Placeholder = "(no policy — start typing or press i to insert a template)"
	ta.Prompt = ""
	ta.ShowLineNumbers = true
	ta.CharLimit = 0
	ta.SetWidth(80)
	ta.SetHeight(20)
	return editorModel{bucket: bucket, ta: ta, mode: modeNormal}
}

// policyLoadedMsg fills the editor with the current bucket policy.
type policyLoadedMsg struct {
	policy string
	err    error
}

// policySavedMsg reports the result of a put-policy call.
type policySavedMsg struct {
	err        error
	backupPath string
}

// policyDeletedMsg reports the result of a delete-policy call.
type policyDeletedMsg struct {
	err        error
	backupPath string
}

// requestSaveMsg bubbles up the user's save request.
type requestSaveMsg struct {
	bucket string
	policy string
}

// requestDeleteMsg bubbles up the user's delete request.
type requestDeleteMsg struct{ bucket string }

// requestReloadMsg bubbles up the user's reload-policy request.
type requestReloadMsg struct{ bucket string }

// editorExternalDoneMsg is emitted after $EDITOR closes; it carries the file path.
type editorExternalDoneMsg struct {
	path string
	err  error
}

func (m editorModel) Init() tea.Cmd { return nil }

// SetSize sizes the editor's textarea for the pane it's being rendered in.
// width and height are the *inner* (post-border, post-padding) dimensions.
func (m *editorModel) SetSize(width, height int) {
	m.width, m.height = width, height
	taW := width - 2
	if taW < 20 {
		taW = 20
	}
	// Reserve rows for the header line + findings (up to ~5 lines) + status.
	taH := height - 7
	if taH < 4 {
		taH = 4
	}
	m.ta.SetWidth(taW)
	m.ta.SetHeight(taH)
}

// Blur drops the editor out of INSERT mode and stops the textarea cursor.
func (m *editorModel) Blur() {
	m.mode = modeNormal
	m.ta.Blur()
}

// Busy reports whether the editor is in any sub-mode that captures the user
// (INSERT or any confirmation prompt). When busy, the app refuses pane
// navigation so the user can't silently abandon a prompt or unsaved edit.
func (m editorModel) Busy() bool { return m.mode != modeNormal }

func (m editorModel) Update(msg tea.Msg) (editorModel, tea.Cmd) {
	switch msg := msg.(type) {
	case policyLoadedMsg:
		m.loaded = true
		if msg.err != nil {
			m.err = msg.err.Error()
			return m, nil
		}
		m.err = ""
		body := msg.policy
		if strings.TrimSpace(body) == "" {
			m.noPolicy = true
			body = ""
		} else {
			m.noPolicy = false
			body = PrettyJSON(body)
		}
		m.original = body
		m.ta.SetValue(body)
		m.refreshFindings()
		// If this was a discard from the dirty-prompt, drop back to NORMAL.
		if m.mode == modeConfirmDirty {
			m.mode = modeNormal
			m.ta.Blur()
			m.info = "discarded local changes"
		}
		return m, nil

	case policySavedMsg:
		if msg.err != nil {
			m.err = msg.err.Error()
			m.info = ""
			// If the save came from a dirty-prompt and failed, return the user
			// to INSERT so they can fix the policy and retry.
			if m.mode == modeConfirmDirty {
				m.mode = modeInsert
				return m, m.ta.Focus()
			}
			return m, nil
		}
		m.err = ""
		m.info = "policy applied"
		m.original = m.ta.Value()
		m.noPolicy = false
		// Successful save from the dirty-prompt → land in NORMAL.
		if m.mode == modeConfirmDirty {
			m.mode = modeNormal
			m.ta.Blur()
		}
		return m, nil

	case policyDeletedMsg:
		if msg.err != nil {
			m.err = msg.err.Error()
			return m, nil
		}
		m.err = ""
		m.info = "policy deleted"
		m.original = ""
		m.noPolicy = true
		m.ta.SetValue("")
		m.findings = nil
		return m, nil

	case editorExternalDoneMsg:
		if msg.err != nil {
			m.err = "external editor: " + msg.err.Error()
			return m, nil
		}
		data, err := os.ReadFile(msg.path)
		_ = os.Remove(msg.path)
		if err != nil {
			m.err = "read back: " + err.Error()
			return m, nil
		}
		m.ta.SetValue(string(data))
		m.refreshFindings()
		m.info = "reloaded from $EDITOR"
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	if m.mode == modeInsert {
		var cmd tea.Cmd
		m.ta, cmd = m.ta.Update(msg)
		m.refreshFindings()
		return m, cmd
	}
	return m, nil
}

func (m editorModel) handleKey(msg tea.KeyMsg) (editorModel, tea.Cmd) {
	key := msg.String()

	switch m.mode {
	case modeConfirmSave:
		switch key {
		case "y", "Y":
			m.mode = modeNormal
			return m, func() tea.Msg {
				return requestSaveMsg{bucket: m.bucket, policy: m.ta.Value()}
			}
		case "n", "N", "esc":
			m.mode = modeNormal
			m.info = "save cancelled"
			return m, nil
		}
		return m, nil

	case modeConfirmDelete:
		switch key {
		case "y", "Y":
			m.mode = modeNormal
			return m, func() tea.Msg { return requestDeleteMsg{bucket: m.bucket} }
		case "n", "N", "esc":
			m.mode = modeNormal
			m.info = "delete cancelled"
			return m, nil
		}
		return m, nil

	case modeInsert:
		if key == "esc" {
			if m.dirty() {
				m.mode = modeConfirmDirty
				m.ta.Blur()
				return m, nil
			}
			m.mode = modeNormal
			m.ta.Blur()
			return m, nil
		}
		var cmd tea.Cmd
		m.ta, cmd = m.ta.Update(msg)
		m.refreshFindings()
		return m, cmd

	case modeConfirmDirty:
		switch key {
		case "s", "S":
			// Save immediately — the user explicitly chose to save, no extra
			// y/n. Mode stays modeConfirmDirty until policySavedMsg returns
			// so we can route the result correctly.
			return m, func() tea.Msg {
				return requestSaveMsg{bucket: m.bucket, policy: m.ta.Value()}
			}
		case "d", "D":
			// Discard local edits by reloading from the server.
			return m, func() tea.Msg { return requestReloadMsg{bucket: m.bucket} }
		case "esc", "c", "C":
			m.mode = modeInsert
			return m, m.ta.Focus()
		}
		return m, nil

	case modeNormal:
		switch key {
		case "i", "a", "enter":
			m.mode = modeInsert
			m.info = ""
			m.err = ""
			cmd := m.ta.Focus()
			return m, cmd
		case "e":
			return m, m.launchExternalEditor()
		case "f":
			m.formatBuffer()
			return m, nil
		case "s":
			return m.beginSave()
		case "d":
			if m.noPolicy {
				m.info = "no policy to delete"
				return m, nil
			}
			m.mode = modeConfirmDelete
			return m, nil
		case "r":
			m.info = "reloading…"
			m.err = ""
			return m, func() tea.Msg { return requestReloadMsg{bucket: m.bucket} }
		case "esc":
			m.info = ""
			m.err = ""
			return m, nil
		}
	}
	return m, nil
}

func (m *editorModel) refreshFindings() {
	v := strings.TrimSpace(m.ta.Value())
	if v == "" {
		m.findings = nil
		return
	}
	m.findings = ValidatePolicyForBucket(v, m.bucket)
}

func (m *editorModel) formatBuffer() {
	v := m.ta.Value()
	pretty := PrettyJSON(v)
	if pretty != v {
		m.ta.SetValue(pretty)
		m.refreshFindings()
		m.info = "formatted"
	}
}

func (m editorModel) beginSave() (editorModel, tea.Cmd) {
	m.refreshFindings()
	if HasErrors(m.findings) {
		m.err = "cannot save: policy has errors (press i to fix)"
		return m, nil
	}
	if strings.TrimSpace(m.ta.Value()) == "" {
		m.err = "policy is empty — use d to delete instead"
		return m, nil
	}
	m.mode = modeConfirmSave
	m.err = ""
	return m, nil
}

func (m editorModel) launchExternalEditor() tea.Cmd {
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		editor = "vi"
	}
	tmp, err := os.CreateTemp("", "bucket-policy-*.json")
	if err != nil {
		return func() tea.Msg { return editorExternalDoneMsg{err: err} }
	}
	if _, err := tmp.WriteString(m.ta.Value()); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return func() tea.Msg { return editorExternalDoneMsg{err: err} }
	}
	tmp.Close()
	path := tmp.Name()

	c := exec.Command(editor, path)
	return tea.ExecProcess(c, func(err error) tea.Msg {
		return editorExternalDoneMsg{path: path, err: err}
	})
}

func (m editorModel) dirty() bool {
	return strings.TrimSpace(m.ta.Value()) != strings.TrimSpace(m.original)
}

func (m editorModel) View() string {
	var b strings.Builder

	// Inline header: bucket name (bold) + mode + dirty marker.
	titleLine := styleTitle.Render("Policy: " + m.bucket)
	hint := m.modeLabel()
	if m.dirty() {
		hint += "  •modified"
	}
	if m.noPolicy {
		hint += "  (no policy)"
	}
	b.WriteString(titleLine + "  " + styleHint.Render(hint))
	b.WriteString("\n")

	b.WriteString(m.ta.View())
	b.WriteString("\n")

	// Validation summary
	b.WriteString(m.findingsSummary())

	// Confirmation / status line
	switch m.mode {
	case modeConfirmSave:
		b.WriteString("\n")
		b.WriteString(styleWarn.Render(fmt.Sprintf("Apply policy to %q? (y/n)", m.bucket)))
	case modeConfirmDelete:
		b.WriteString("\n")
		b.WriteString(styleErr.Render(fmt.Sprintf("Delete policy on %q? (y/n)", m.bucket)))
	case modeConfirmDirty:
		b.WriteString("\n")
		b.WriteString(styleWarn.Render("Unsaved changes — (s)ave  (d)iscard  (c)ancel"))
	default:
		if m.err != "" {
			b.WriteString("\n")
			b.WriteString(styleErr.Render(m.err))
		} else if m.info != "" {
			b.WriteString("\n")
			b.WriteString(styleOK.Render(m.info))
		}
	}
	return b.String()
}

func (m editorModel) modeLabel() string {
	switch m.mode {
	case modeInsert:
		return "-- INSERT --"
	case modeConfirmDirty:
		return "-- UNSAVED --"
	case modeConfirmSave, modeConfirmDelete:
		return "-- CONFIRM --"
	default:
		return "-- NORMAL --"
	}
}

func (m editorModel) findingsSummary() string {
	if !m.loaded {
		return styleHint.Render("loading…")
	}
	if len(m.findings) == 0 {
		if strings.TrimSpace(m.ta.Value()) == "" {
			return styleHint.Render("(empty)")
		}
		return styleOK.Render("✓ policy looks valid")
	}
	var errs, warns int
	for _, f := range m.findings {
		if f.Severity == SevError {
			errs++
		} else {
			warns++
		}
	}
	header := fmt.Sprintf("%d error(s), %d warning(s)", errs, warns)
	if errs > 0 {
		header = styleErr.Render(header)
	} else {
		header = styleWarn.Render(header)
	}
	// Show up to 3 findings.
	var lines []string
	lines = append(lines, header)
	limit := 3
	for i, f := range m.findings {
		if i >= limit {
			lines = append(lines, styleHint.Render(fmt.Sprintf("…and %d more", len(m.findings)-limit)))
			break
		}
		text := "• " + f.String()
		if f.Severity == SevError {
			text = styleErr.Render(text)
		} else {
			text = styleWarn.Render(text)
		}
		lines = append(lines, text)
	}
	return strings.Join(lines, "\n")
}
