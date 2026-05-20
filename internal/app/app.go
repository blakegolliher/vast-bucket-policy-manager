package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	paneProfiles = iota
	paneBuckets
	paneEditor
	numPanes
)

type app struct {
	profiles     []string
	profilesList list.Model
	bucketsList  list.Model
	editor       editorModel
	modal        *manualEntry
	quitPrompt   bool

	focus int

	client         *Client
	currentProfile string
	currentBucket  string

	tlsSkip bool

	// status displayed in the bottom bar; cleared on next action
	status     string
	statusKind string // "", "ok", "err", "warn"

	width, height int
	ctx           context.Context
}

func newApp(ctx context.Context) app {
	pl := newCompactList("Profiles", false)
	pl.SetItems(formatProfiles(DiscoverProfiles(), ""))

	bl := newCompactList("Buckets", true)

	return app{
		profiles:     DiscoverProfiles(),
		profilesList: pl,
		bucketsList:  bl,
		editor:       newEditorModel(""),
		focus:        paneProfiles,
		// VAST clusters commonly serve self-signed certs in lab environments,
		// so we default to skipping TLS verification. If the cert is valid
		// the connection still succeeds; if not we just don't error out.
		// Toggle off with Ctrl+T when on production AWS.
		tlsSkip: true,
		ctx:     ctx,
	}
}

func (a app) Init() tea.Cmd { return nil }

// --- top-level update ----------------------------------------------------

func (a app) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Quit confirmation owns input while open — y exits, anything else cancels.
	if a.quitPrompt {
		return a.updateQuitPrompt(msg)
	}
	// Modal owns input while open.
	if a.modal != nil {
		return a.updateModal(msg)
	}

	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = m.Width, m.Height
		a.layout()
		return a, nil

	case tea.KeyMsg:
		// Ctrl+C always quits, even mid-edit or mid-prompt.
		if m.String() == "ctrl+c" {
			return a, tea.Quit
		}

		// When the editor is captured (INSERT or any confirm prompt) we
		// surrender all global keys to it. The user must Esc out of INSERT
		// (which may itself raise the unsaved-changes prompt) or answer the
		// active prompt before any pane navigation is allowed.
		if a.focus == paneEditor && a.editor.Busy() {
			return a.updateFocusedPane(msg)
		}

		// Other global keys (NORMAL mode in editor, or any other pane).
		switch m.String() {
		case "ctrl+t":
			a.tlsSkip = !a.tlsSkip
			if a.client != nil && a.currentProfile != "" {
				a.setStatus("reconnecting with new TLS setting…", "")
				return a, cmdConnectProfile(a.ctx, a.currentProfile, a.tlsSkip)
			}
			return a, nil
		case "ctrl+1":
			if a.blocksDirtyNav(paneProfiles) {
				return a, nil
			}
			a.setFocus(paneProfiles)
			return a, nil
		case "ctrl+2":
			if a.blocksDirtyNav(paneBuckets) {
				return a, nil
			}
			a.setFocus(paneBuckets)
			return a, nil
		case "ctrl+3":
			a.setFocus(paneEditor)
			return a, nil
		case "tab":
			next := (a.focus + 1) % numPanes
			if a.blocksDirtyNav(next) {
				return a, nil
			}
			a.setFocus(next)
			return a, nil
		case "shift+tab":
			next := (a.focus + numPanes - 1) % numPanes
			if a.blocksDirtyNav(next) {
				return a, nil
			}
			a.setFocus(next)
			return a, nil
		}

		// Left/Right arrows navigate between panes. Suppressed only when the
		// bucket filter input is active (so arrow keys move within the filter
		// text instead of the panes).
		if m.String() == "left" || m.String() == "right" {
			filterActive := a.focus == paneBuckets && a.bucketsList.FilterState() == list.Filtering
			if !filterActive {
				if m.String() == "left" && a.focus > 0 {
					if a.blocksDirtyNav(a.focus - 1) {
						return a, nil
					}
					a.setFocus(a.focus - 1)
				}
				if m.String() == "right" && a.focus < numPanes-1 {
					if a.blocksDirtyNav(a.focus + 1) {
						return a, nil
					}
					a.setFocus(a.focus + 1)
				}
				return a, nil
			}
		}

		// 'n' opens manual entry. Editor capture above already prevents this
		// firing while in INSERT/confirm modes.
		if m.String() == "n" {
			me := newManualEntry(a.tlsSkip)
			a.modal = &me
			return a, nil
		}

		// 'q' opens the quit confirmation, except while typing into the
		// bucket filter input (so users can filter for buckets named "q…").
		if m.String() == "q" {
			filterActive := a.focus == paneBuckets && a.bucketsList.FilterState() == list.Filtering
			if !filterActive {
				a.quitPrompt = true
				return a, nil
			}
		}

	// Cross-screen messages — handled regardless of focus.
	case connectAttemptMsg:
		if m.err != nil {
			a.setStatus("connect failed: "+m.err.Error(), "err")
			// Do NOT mutate a.currentProfile / a.client on failure — leave
			// any prior successful connection's state intact.
			return a, nil
		}
		a.client = m.client
		a.currentProfile = m.profile // "" for manual entry
		// Refresh the profiles list to mark the new connection.
		a.profilesList.SetItems(formatProfiles(a.profiles, a.currentProfile))
		who := a.currentProfile
		if who == "" {
			who = "manual"
		}
		a.setStatus(fmt.Sprintf("connected · %s", who), "ok")
		// Auto-shift focus to buckets and load them.
		a.setFocus(paneBuckets)
		a.bucketsList.SetItems(nil)
		a.bucketsList.Title = "Buckets · loading…"
		return a, cmdLoadBuckets(a.ctx, a.client)

	case bucketsLoadedMsg:
		if m.err != nil {
			a.setStatus("list buckets: "+m.err.Error(), "err")
			a.bucketsList.Title = "Buckets"
			return a, nil
		}
		items := make([]list.Item, len(m.names))
		for i, n := range m.names {
			items[i] = simpleItem{name: n}
		}
		a.bucketsList.SetItems(items)
		a.bucketsList.Title = formatTitle("Buckets", len(items))
		a.setStatus(fmt.Sprintf("%d bucket(s)", len(items)), "")
		return a, nil

	case policyLoadedMsg, policySavedMsg, policyDeletedMsg, editorExternalDoneMsg:
		// Always route policy results to the editor.
		var cmd tea.Cmd
		a.editor, cmd = a.editor.Update(msg)
		// Surface error/info into the global status bar too.
		if perr := extractPolicyErr(msg); perr != "" {
			a.setStatus(perr, "err")
		} else {
			switch r := msg.(type) {
			case policySavedMsg:
				if r.backupPath != "" {
					a.setStatus("policy applied · backup: "+r.backupPath, "ok")
				}
			case policyDeletedMsg:
				if r.backupPath != "" {
					a.setStatus("policy deleted · backup: "+r.backupPath, "ok")
				}
			}
		}
		return a, cmd

	case requestSaveMsg:
		a.setStatus("applying policy…", "")
		var cmd tea.Cmd
		a.editor, cmd = a.editor.Update(msg)
		return a, tea.Batch(cmd, cmdSavePolicy(a.ctx, a.client, m.bucket, m.policy))

	case requestDeleteMsg:
		a.setStatus("deleting policy…", "")
		return a, cmdDeletePolicy(a.ctx, a.client, m.bucket)

	case requestReloadMsg:
		a.setStatus("reloading policy…", "")
		return a, cmdLoadPolicy(a.ctx, a.client, m.bucket)
	}

	// Route key events / list updates to the focused pane.
	return a.updateFocusedPane(msg)
}

func (a app) updateQuitPrompt(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "y", "Y":
			return a, tea.Quit
		case "ctrl+c":
			return a, tea.Quit
		default:
			// Any other key (including n/N/Esc) cancels.
			a.quitPrompt = false
			return a, nil
		}
	}
	return a, nil
}

func (a app) updateModal(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = m.Width, m.Height
		a.layout()
	case tea.KeyMsg:
		if m.String() == "ctrl+c" {
			return a, tea.Quit
		}
	case manualSubmitMsg:
		// Don't touch a.currentProfile / a.client until the attempt succeeds;
		// connectAttemptMsg will overwrite them on success.
		a.tlsSkip = m.conn.InsecureTLS
		a.modal = nil
		a.setStatus("connecting…", "")
		return a, cmdConnectManual(a.ctx, m.conn)
	case manualCancelMsg:
		a.modal = nil
		return a, nil
	}
	var cmd tea.Cmd
	updated, cmd := a.modal.Update(msg)
	a.modal = &updated
	return a, cmd
}

func (a app) updateFocusedPane(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch a.focus {
	case paneProfiles:
		if k, ok := msg.(tea.KeyMsg); ok && k.String() == "enter" {
			if it, ok := a.profilesList.SelectedItem().(simpleItem); ok {
				name := rawProfileName(it.name)
				// Don't set a.currentProfile here — the connect attempt
				// may fail. connectAttemptMsg's success path is the only
				// place that promotes the attempted profile to "current".
				a.setStatus(fmt.Sprintf("connecting to %s…", name), "")
				return a, cmdConnectProfile(a.ctx, name, a.tlsSkip)
			}
		}
		var cmd tea.Cmd
		a.profilesList, cmd = a.profilesList.Update(msg)
		return a, cmd

	case paneBuckets:
		if k, ok := msg.(tea.KeyMsg); ok {
			// Don't intercept while filter input is active.
			if a.bucketsList.FilterState() != list.Filtering {
				switch k.String() {
				case "enter":
					if it, ok := a.bucketsList.SelectedItem().(simpleItem); ok {
						a.currentBucket = it.name
						a.editor = newEditorModel(it.name)
						a.editor.SetSize(a.editorPaneInnerSize())
						a.setFocus(paneEditor)
						a.setStatus("loading policy…", "")
						return a, cmdLoadPolicy(a.ctx, a.client, it.name)
					}
				case "r":
					if a.client != nil {
						a.setStatus("refreshing…", "")
						return a, cmdLoadBuckets(a.ctx, a.client)
					}
				}
			}
		}
		var cmd tea.Cmd
		a.bucketsList, cmd = a.bucketsList.Update(msg)
		return a, cmd

	case paneEditor:
		var cmd tea.Cmd
		a.editor, cmd = a.editor.Update(msg)
		return a, cmd
	}
	return a, nil
}

func (a *app) setFocus(p int) {
	if p == a.focus {
		return
	}
	// Leaving editor — drop INSERT mode so the cursor stops blinking.
	if a.focus == paneEditor && p != paneEditor {
		a.editor.Blur()
	}
	a.focus = p
}

// blocksDirtyNav refuses to leave the editor pane while there are unsaved
// changes and surfaces the save/discard prompt instead. Returns true if
// the caller should abort the navigation.
func (a *app) blocksDirtyNav(newFocus int) bool {
	if a.focus == paneEditor && newFocus != paneEditor && a.editor.dirty() {
		a.editor.mode = modeConfirmDirty
		return true
	}
	return false
}

func (a *app) setStatus(msg, kind string) {
	a.status = msg
	a.statusKind = kind
}

// editorPaneInnerSize returns the (width, height) inside the editor pane's
// border for sizing the textarea.
func (a app) editorPaneInnerSize() (int, int) {
	_, _, rightW, contentH := a.paneDimensions()
	return rightW - 4, contentH - 2
}

// paneDimensions computes the outer width/height of each pane based on the
// terminal size.
func (a app) paneDimensions() (left, mid, right, height int) {
	w := a.width
	if w < 60 {
		w = 60
	}
	// reserve 2 rows for status + help
	height = a.height - 3
	if height < 12 {
		height = 12
	}
	left = clamp(w*18/100, 18, 30)
	mid = clamp(w*22/100, 22, 36)
	right = w - left - mid
	if right < 30 {
		right = 30
	}
	return
}

func (a *app) layout() {
	leftW, midW, rightW, h := a.paneDimensions()
	// Bubbles list wants inner (content) size.
	a.profilesList.SetSize(leftW-4, h-2)
	a.bucketsList.SetSize(midW-4, h-2)
	a.editor.SetSize(rightW-4, h-2)
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// --- view ----------------------------------------------------------------

func (a app) View() string {
	if a.quitPrompt {
		return quitConfirmBox(a.width, a.height)
	}
	if a.modal != nil {
		return modalBox(a.modal.View(), a.width, a.height)
	}

	leftW, midW, rightW, h := a.paneDimensions()

	leftPane := renderPane(a.profilesList.View(), leftW, h, a.focus == paneProfiles)
	midPane := renderPane(a.bucketsList.View(), midW, h, a.focus == paneBuckets)

	var editorBody string
	if a.currentBucket == "" {
		editorBody = renderPane(emptyPane("(select a bucket on the left)", rightW, h), rightW, h, a.focus == paneEditor)
	} else {
		editorBody = renderPane(a.editor.View(), rightW, h, a.focus == paneEditor)
	}

	row := lipgloss.JoinHorizontal(lipgloss.Top, leftPane, midPane, editorBody)

	status := statusBarLine(a.width, a.client != nil, a.currentProfile, a.tlsSkip, a.status, a.statusKind)
	help := helpLine(a.focus, a.editor.mode, a.modal != nil, a.width)

	return strings.Join([]string{row, status, help}, "\n")
}

// extractPolicyErr peeks at result messages so the bottom status bar can
// echo errors even though the editor displays them too.
func extractPolicyErr(msg tea.Msg) string {
	switch m := msg.(type) {
	case policyLoadedMsg:
		if m.err != nil {
			return "load policy: " + m.err.Error()
		}
	case policySavedMsg:
		if m.err != nil {
			return "save policy: " + m.err.Error()
		}
	case policyDeletedMsg:
		if m.err != nil {
			return "delete policy: " + m.err.Error()
		}
	}
	return ""
}

// --- async commands ------------------------------------------------------

func cmdConnectProfile(ctx context.Context, profile string, insecure bool) tea.Cmd {
	return func() tea.Msg {
		pd := LoadProfileData(profile)
		conn := Connection{
			Profile:     profile,
			Endpoint:    pd.Endpoint,
			Region:      pd.Region,
			InsecureTLS: insecure,
		}
		cli, err := NewClient(ctx, conn)
		if err != nil {
			return connectAttemptMsg{profile: profile, err: err}
		}
		if _, err := cli.ListBuckets(ctx); err != nil {
			return connectAttemptMsg{profile: profile, err: fmt.Errorf("test call failed: %w", err)}
		}
		return connectAttemptMsg{profile: profile, client: cli}
	}
}

func cmdConnectManual(ctx context.Context, conn Connection) tea.Cmd {
	return func() tea.Msg {
		cli, err := NewClient(ctx, conn)
		if err != nil {
			return connectAttemptMsg{err: err}
		}
		if _, err := cli.ListBuckets(ctx); err != nil {
			return connectAttemptMsg{err: fmt.Errorf("test call failed: %w", err)}
		}
		return connectAttemptMsg{client: cli}
	}
}

func cmdLoadBuckets(ctx context.Context, cli *Client) tea.Cmd {
	return func() tea.Msg {
		if cli == nil {
			return bucketsLoadedMsg{err: fmt.Errorf("not connected")}
		}
		names, err := cli.ListBuckets(ctx)
		return bucketsLoadedMsg{names: names, err: err}
	}
}

func cmdLoadPolicy(ctx context.Context, cli *Client, bucket string) tea.Cmd {
	return func() tea.Msg {
		if cli == nil {
			return policyLoadedMsg{err: fmt.Errorf("not connected")}
		}
		pol, err := cli.GetBucketPolicy(ctx, bucket)
		return policyLoadedMsg{policy: pol, err: err}
	}
}

func cmdSavePolicy(ctx context.Context, cli *Client, bucket, policy string) tea.Cmd {
	return func() tea.Msg {
		if cli == nil {
			return policySavedMsg{err: fmt.Errorf("not connected")}
		}
		// Backup the server's current state before applying. If the backup
		// can't be written we refuse to proceed — the user explicitly asked
		// for "backup first before applying any change."
		current, err := cli.GetBucketPolicy(ctx, bucket)
		if err != nil {
			return policySavedMsg{err: fmt.Errorf("backup: fetch current policy: %w", err)}
		}
		if _, err := WriteBackup(cli.Endpoint(), bucket, "before-save", current); err != nil {
			return policySavedMsg{err: fmt.Errorf("backup: %w", err)}
		}
		// Also snapshot what we're about to apply, so the trail captures
		// both "what we had" and "what edits we made."
		afterPath, err := WriteBackup(cli.Endpoint(), bucket, "after-save", policy)
		if err != nil {
			return policySavedMsg{err: fmt.Errorf("backup: %w", err)}
		}
		return policySavedMsg{
			err:        cli.PutBucketPolicy(ctx, bucket, policy),
			backupPath: afterPath,
		}
	}
}

func cmdDeletePolicy(ctx context.Context, cli *Client, bucket string) tea.Cmd {
	return func() tea.Msg {
		if cli == nil {
			return policyDeletedMsg{err: fmt.Errorf("not connected")}
		}
		current, err := cli.GetBucketPolicy(ctx, bucket)
		if err != nil {
			return policyDeletedMsg{err: fmt.Errorf("backup: fetch current policy: %w", err)}
		}
		path, err := WriteBackup(cli.Endpoint(), bucket, "before-delete", current)
		if err != nil {
			return policyDeletedMsg{err: fmt.Errorf("backup: %w", err)}
		}
		return policyDeletedMsg{
			err:        cli.DeleteBucketPolicy(ctx, bucket),
			backupPath: path,
		}
	}
}

// bucketsLoadedMsg + connectAttemptMsg used to live in their old screens; they
// now live here (cross-screen messages).
type bucketsLoadedMsg struct {
	names []string
	err   error
}

type connectAttemptMsg struct {
	client  *Client
	profile string // the profile name the attempt was for; "" for manual entry
	err     error
}

// Run starts the TUI program and blocks until the user quits.
func Run() error {
	ctx := context.Background()
	a := newApp(ctx)
	p := tea.NewProgram(a, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
