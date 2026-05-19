package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// manualEntry is the popup that captures endpoint + creds when the user wants
// to connect without an AWS profile.
type manualEntry struct {
	inputs   []textinput.Model
	focus    int
	insecure bool
	err      string
}

const (
	mEndpoint  = 0
	mAccessKey = 1
	mSecretKey = 2
	mRegion    = 3
	mInsecure  = 4
	mSubmit    = 5
	mFocusSlots = 6
	mNumInputs  = 4
)

func newManualEntry(initialInsecure bool) manualEntry {
	mk := func(placeholder string, masked bool) textinput.Model {
		ti := textinput.New()
		ti.Placeholder = placeholder
		ti.Prompt = "  "
		ti.CharLimit = 256
		ti.Width = 50
		if masked {
			ti.EchoMode = textinput.EchoPassword
			ti.EchoCharacter = '•'
		}
		return ti
	}

	in := make([]textinput.Model, mNumInputs)
	in[mEndpoint] = mk("https://s3.example.com", false)
	in[mAccessKey] = mk("access key id", false)
	in[mSecretKey] = mk("secret access key", true)
	in[mRegion] = mk("us-east-1", false)
	in[mEndpoint].Focus()

	return manualEntry{inputs: in, insecure: initialInsecure}
}

// manualSubmitMsg bubbles up after the user submits.
type manualSubmitMsg struct{ conn Connection }
type manualCancelMsg struct{}

func (m manualEntry) Update(msg tea.Msg) (manualEntry, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc":
			return m, func() tea.Msg { return manualCancelMsg{} }
		case "tab", "down":
			m.focus = (m.focus + 1) % mFocusSlots
			m.refocus()
			return m, nil
		case "shift+tab", "up":
			m.focus--
			if m.focus < 0 {
				m.focus = mFocusSlots - 1
			}
			m.refocus()
			return m, nil
		case "enter":
			if m.focus == mSubmit {
				return m.submit()
			}
			if m.focus == mInsecure {
				m.insecure = !m.insecure
				return m, nil
			}
			m.focus++
			m.refocus()
			return m, nil
		case " ", "space":
			if m.focus == mInsecure {
				m.insecure = !m.insecure
				return m, nil
			}
		}
	}

	if m.focus < mNumInputs {
		var cmd tea.Cmd
		m.inputs[m.focus], cmd = m.inputs[m.focus].Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *manualEntry) refocus() {
	for i := range m.inputs {
		if i == m.focus {
			m.inputs[i].Focus()
		} else {
			m.inputs[i].Blur()
		}
	}
}

func (m manualEntry) submit() (manualEntry, tea.Cmd) {
	conn := Connection{
		Endpoint:    m.inputs[mEndpoint].Value(),
		AccessKey:   m.inputs[mAccessKey].Value(),
		SecretKey:   m.inputs[mSecretKey].Value(),
		Region:      m.inputs[mRegion].Value(),
		InsecureTLS: m.insecure,
	}.Trim()

	if conn.Endpoint == "" {
		m.err = "endpoint is required"
		return m, nil
	}
	if conn.AccessKey == "" || conn.SecretKey == "" {
		m.err = "access key and secret key are required"
		return m, nil
	}
	if conn.Region == "" {
		conn.Region = "us-east-1"
	}
	return m, func() tea.Msg { return manualSubmitMsg{conn: conn} }
}

func (m manualEntry) View() string {
	var b strings.Builder
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	b.WriteString(title.Render("New connection"))
	b.WriteString("\n\n")

	labels := []string{"Endpoint", "Access key", "Secret key", "Region"}
	label := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	for i, ti := range m.inputs {
		b.WriteString(label.Render(fmt.Sprintf("%-11s", labels[i])))
		b.WriteString("\n")
		b.WriteString(ti.View())
		b.WriteString("\n")
	}

	check := "[ ]"
	if m.insecure {
		check = "[✓]"
	}
	line := fmt.Sprintf("%s  Skip TLS verification", check)
	style := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	if m.focus == mInsecure {
		style = lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true)
	}
	b.WriteString("\n" + style.Render(line) + "\n\n")

	btnStyle := lipgloss.NewStyle().Padding(0, 2).Border(lipgloss.RoundedBorder())
	if m.focus == mSubmit {
		btnStyle = btnStyle.Foreground(lipgloss.Color("0")).Background(lipgloss.Color("39"))
	}
	b.WriteString(btnStyle.Render("Connect"))

	if m.err != "" {
		b.WriteString("\n\n")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render(m.err))
	}

	return b.String()
}
