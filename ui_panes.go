package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/lipgloss"
)

// simpleItem is a bare-bones list.Item: title only, no description.
type simpleItem struct{ name string }

func (s simpleItem) Title() string       { return s.name }
func (s simpleItem) Description() string { return "" }
func (s simpleItem) FilterValue() string { return s.name }

// newCompactList returns a list configured for a narrow pane.
func newCompactList(title string, filterEnabled bool) list.Model {
	d := list.NewDefaultDelegate()
	d.ShowDescription = false
	d.SetSpacing(0)

	l := list.New(nil, d, 0, 0)
	l.Title = title
	l.SetShowStatusBar(false)
	l.SetShowHelp(false)
	l.SetFilteringEnabled(filterEnabled)
	l.SetShowFilter(filterEnabled)
	l.Styles.Title = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).Padding(0, 1)
	return l
}

// shared text styles, also used by ui_editor
var (
	styleTitle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	styleErr   = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	styleWarn  = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styleOK    = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	styleHint  = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)

// pane styles
var (
	paneBorder       = lipgloss.RoundedBorder()
	paneStyleBase    = lipgloss.NewStyle().Border(paneBorder).BorderForeground(lipgloss.Color("240")).Padding(0, 1)
	paneStyleFocused = lipgloss.NewStyle().Border(paneBorder).BorderForeground(lipgloss.Color("39")).Padding(0, 1)

	statusStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	statusErrStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	statusOKStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	statusWarnStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	statusBadgeOn    = lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("214")).Padding(0, 1)
	statusBadgeOff   = lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("240")).Padding(0, 1)
	statusConnected  = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	statusDisconnect = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
)

// renderPane wraps content in a border, painting it differently when focused.
func renderPane(content string, width, height int, focused bool) string {
	style := paneStyleBase
	if focused {
		style = paneStyleFocused
	}
	// Subtract border (2) and horizontal padding (2) from the requested width.
	inner := width - 4
	if inner < 1 {
		inner = 1
	}
	innerH := height - 2
	if innerH < 1 {
		innerH = 1
	}
	return style.Width(inner).Height(innerH).Render(content)
}

// emptyPane renders a centered placeholder string, used when a pane has
// nothing to show yet (e.g., editor before a bucket is picked).
func emptyPane(msg string, width, height int) string {
	inner := width - 4
	if inner < 1 {
		inner = 1
	}
	innerH := height - 2
	if innerH < 1 {
		innerH = 1
	}
	return lipgloss.NewStyle().
		Width(inner).Height(innerH).
		Align(lipgloss.Center, lipgloss.Center).
		Foreground(lipgloss.Color("240")).
		Render(msg)
}

// statusBarLine builds the bottom status line.
func statusBarLine(width int, connected bool, profile string, tlsSkip bool, msg string, msgKind string) string {
	var left strings.Builder
	if connected {
		left.WriteString(statusConnected.Render("● connected"))
		if profile != "" {
			left.WriteString(statusStyle.Render(" · " + profile))
		}
	} else {
		left.WriteString(statusDisconnect.Render("○ disconnected"))
	}

	tlsBadge := "TLS-skip OFF"
	tlsStyle := statusBadgeOff
	if tlsSkip {
		tlsBadge = "TLS-skip ON"
		tlsStyle = statusBadgeOn
	}
	left.WriteString("  " + tlsStyle.Render(tlsBadge))

	if msg != "" {
		var s lipgloss.Style
		switch msgKind {
		case "err":
			s = statusErrStyle
		case "ok":
			s = statusOKStyle
		case "warn":
			s = statusWarnStyle
		default:
			s = statusStyle
		}
		left.WriteString("  " + s.Render(msg))
	}

	out := left.String()
	// Truncate if too wide for the terminal.
	plain := lipgloss.Width(out)
	if plain > width {
		// Just let lipgloss clip via Width — visual truncation.
		out = lipgloss.NewStyle().Width(width).Render(out)
	}
	return out
}

// helpLine builds the keybind hint shown below the status bar.
func helpLine(focus int, editorMode editorMode, modalOpen bool, width int) string {
	if modalOpen {
		return statusStyle.Render(" tab navigate · space toggle · enter submit · esc cancel · ctrl+c quit")
	}
	var s string
	switch focus {
	case paneProfiles:
		s = " enter connect · n new connection · ctrl+t toggle TLS-skip · tab next pane · q quit"
	case paneBuckets:
		s = " enter view policy · r refresh · / filter · n new connection · tab cycle pane · q quit"
	case paneEditor:
		switch editorMode {
		case modeInsert:
			s = " esc leave INSERT · ctrl+c quit"
		case modeConfirmSave, modeConfirmDelete:
			s = " y confirm · n cancel"
		case modeConfirmDirty:
			s = " s save · d discard · c cancel"
		default:
			s = " i edit · e $EDITOR · f format · s save · d delete · r reload · ← back · tab next pane · q quit"
		}
	}
	return statusStyle.Render(s)
}

// formatProfiles returns the list items, marking the connected one with a bullet.
func formatProfiles(profiles []string, connected string) []list.Item {
	items := make([]list.Item, len(profiles))
	for i, p := range profiles {
		name := "  " + p
		if p == connected {
			name = "• " + p
		}
		items[i] = simpleItem{name: name}
	}
	return items
}

// rawProfileName strips the bullet/space prefix added by formatProfiles.
func rawProfileName(displayed string) string {
	displayed = strings.TrimPrefix(displayed, "• ")
	displayed = strings.TrimPrefix(displayed, "  ")
	return displayed
}

// quitConfirmBox renders the y/N quit prompt centered on the screen.
func quitConfirmBox(termW, termH int) string {
	body := lipgloss.JoinVertical(lipgloss.Center,
		lipgloss.NewStyle().Bold(true).Render("Quit?"),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Render("(y) yes    (any other key) cancel"),
	)
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("196")).
		Padding(1, 3).
		Render(body)
	return lipgloss.Place(termW, termH, lipgloss.Center, lipgloss.Center, box)
}

// modalBox wraps content in a centered, bordered box for the manual-entry
// dialog. width and height are the terminal dimensions.
func modalBox(content string, termW, termH int) string {
	w := termW - 10
	if w > 70 {
		w = 70
	}
	if w < 30 {
		w = 30
	}
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("39")).
		Padding(1, 2).
		Width(w).
		Render(content)
	return lipgloss.Place(termW, termH, lipgloss.Center, lipgloss.Center, box)
}

// formatTitle adds a count suffix to a pane title.
func formatTitle(prefix string, count int) string {
	if count <= 0 {
		return prefix
	}
	return fmt.Sprintf("%s (%d)", prefix, count)
}
