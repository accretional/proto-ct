// Package dashboard provides a polling terminal monitor framework.
// Consumers implement Panel and call Run; all terminal and timing concerns
// live here.
package dashboard

import (
	"fmt"
	"math"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// ANSI color/style codes for use in Panel.Render implementations.
const (
	Reset  = "\033[0m"
	Bold   = "\033[1m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
	Gray   = "\033[90m"
	Red    = "\033[31m"
)

const clearScreen = "\033[2J\033[H"

// Panel is implemented by each service-specific monitor component.
// Update fetches or parses the latest state from whatever source the panel
// uses. Render produces an ANSI-colored string for the current width; it
// should end with a trailing newline.
type Panel interface {
	Update()
	Render(width int) string
}

// Run calls Update then Render on each panel every refresh interval,
// clears the screen, and prints the assembled output. It exits cleanly
// on SIGINT or SIGTERM.
func Run(refresh time.Duration, panels ...Panel) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	redraw := func() {
		w := TermWidth()
		var sb strings.Builder
		sb.WriteString(clearScreen)
		for _, p := range panels {
			p.Update()
			sb.WriteString(p.Render(w))
		}
		fmt.Fprintf(&sb, "%s  Ctrl+C to quit  updated: %s%s\n",
			Gray, time.Now().Format("15:04:05"), Reset)
		fmt.Print(sb.String())
	}

	redraw()

	ticker := time.NewTicker(refresh)
	defer ticker.Stop()
	for {
		select {
		case <-sig:
			fmt.Print(clearScreen)
			return
		case <-ticker.C:
			redraw()
		}
	}
}

// TermWidth returns the terminal column count, falling back to $COLUMNS then 80.
func TermWidth() int {
	type winsize struct{ Row, Col, Xpixel, Ypixel uint16 }
	ws := winsize{}
	syscall.Syscall(syscall.SYS_IOCTL, uintptr(os.Stdout.Fd()), syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(&ws)))
	if ws.Col > 0 {
		return int(ws.Col)
	}
	if s := os.Getenv("COLUMNS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return 80
}

// Header returns a full-width "── Title ───…" section header.
func Header(title string, w int) string {
	line := "── " + title + " "
	if rem := w - len(line) - 1; rem > 0 {
		line += strings.Repeat("─", rem)
	}
	return Bold + Cyan + line + Reset
}

// ProgressBar renders a w-character █/░ bar for pct ∈ [0, 100].
func ProgressBar(pct float64, w int) string {
	n := min(int(math.Round(float64(w)*pct/100.0)), w)
	return Green + strings.Repeat("█", n) + Gray + strings.Repeat("░", w-n) + Reset
}

// CommaSep formats n with thousands separators.
func CommaSep(n int64) string {
	s := strconv.FormatInt(n, 10)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := pre; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

// FormatETA formats seconds as ~Xs / ~Xm / ~X.Xh.
func FormatETA(sec float64) string {
	switch {
	case sec < 90:
		return fmt.Sprintf("~%.0fs", sec)
	case sec < 5400:
		return fmt.Sprintf("~%.0fm", sec/60)
	default:
		return fmt.Sprintf("~%.1fh", sec/3600)
	}
}
