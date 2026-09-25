---
version: alpha
name: FR_OS Control Plane
description: >-
  Visual identity of the FR_OS router webUI: a calm, dense, utilitarian
  control panel for a firewall/router that people run at home or in a
  small office. Values below are the ones src/frfw/webui/templates/base.html
  actually uses.
colors:
  primary: "#17324D"
  primary-hover: "#204A72"
  on-primary: "#FFFFFF"
  nav-link: "#DCE7F0"
  secondary: "#5C6B78"
  on-secondary: "#FFFFFF"
  neutral: "#F2F4F6"
  surface: "#FFFFFF"
  surface-subtle: "#EEF2F6"
  on-surface: "#1A1A1A"
  label: "#333333"
  muted: "#666677"
  outline: "#DDE3E8"
  outline-input: "#C7CFD6"
  success: "#2F7D32"
  success-container: "#E1F2E1"
  on-success-container: "#1C4B1E"
  warning: "#B8860B"
  warning-container: "#FFF4D6"
  on-warning-container: "#6B4E00"
  error: "#A83232"
  error-hover: "#C23D3D"
  error-container: "#FBE1E1"
  on-error-container: "#6B1717"
  on-error: "#FFFFFF"
  terminal: "#0D1117"
  on-terminal: "#9BE29B"
  terminal-alert: "#FF8A8A"
  terminal-meta: "#7D8590"
typography:
  headline-lg:
    fontFamily: system-ui, -apple-system, sans-serif
    fontSize: 1.4rem
    fontWeight: 700
    lineHeight: 1.25
  headline-sm:
    fontFamily: system-ui, -apple-system, sans-serif
    fontSize: 1rem
    fontWeight: 700
    lineHeight: 1.3
  brand:
    fontFamily: system-ui, -apple-system, sans-serif
    fontSize: 1.05rem
    fontWeight: 700
    lineHeight: 1.2
  body-md:
    fontFamily: system-ui, -apple-system, sans-serif
    fontSize: 1rem
    fontWeight: 400
    lineHeight: 1.5
  body-sm:
    fontFamily: system-ui, -apple-system, sans-serif
    fontSize: 0.88rem
    fontWeight: 400
    lineHeight: 1.4
  label-md:
    fontFamily: system-ui, -apple-system, sans-serif
    fontSize: 0.82rem
    fontWeight: 600
    lineHeight: 1.3
  caption:
    fontFamily: system-ui, -apple-system, sans-serif
    fontSize: 0.85rem
    fontWeight: 400
    lineHeight: 1.4
  label-sm:
    fontFamily: system-ui, -apple-system, sans-serif
    fontSize: 0.78rem
    fontWeight: 400
    lineHeight: 1.3
  stat-label:
    fontFamily: system-ui, -apple-system, sans-serif
    fontSize: 0.75rem
    fontWeight: 400
    lineHeight: 1.3
    letterSpacing: 0.03em
  data-mono:
    fontFamily: ui-monospace, SF Mono, Menlo, monospace
    fontSize: 0.8rem
    fontWeight: 400
    lineHeight: 1.45
rounded:
  none: 0px
  sm: 4px
  md: 6px
  full: 999px
spacing:
  content-max-width: 980px
  xs: 0.2rem
  sm: 0.4rem
  md: 0.6rem
  lg: 1rem
  xl: 1.2rem
  xxl: 1.5rem
  card-padding-y: 1rem
  card-padding-x: 1.2rem
  card-gap: 1.2rem
  page-gutter: 1rem
  header-padding-y: 0.75rem
  header-padding-x: 1.25rem
  input-max-width: 340px
components:
  header:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.nav-link}"
    typography: "{typography.body-md}"
    padding: 0.75rem
  header-link-active:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary}"
  page:
    backgroundColor: "{colors.neutral}"
    textColor: "{colors.on-surface}"
    width: 980px
  card:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.on-surface}"
    rounded: "{rounded.md}"
    padding: 1rem
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.sm}"
    padding: 0.45rem
  button-primary-hover:
    backgroundColor: "{colors.primary-hover}"
    textColor: "{colors.on-primary}"
  button-secondary:
    backgroundColor: "{colors.secondary}"
    textColor: "{colors.on-secondary}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.sm}"
    padding: 0.45rem
  button-danger:
    backgroundColor: "{colors.error}"
    textColor: "{colors.on-error}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.sm}"
    padding: 0.45rem
  button-danger-hover:
    backgroundColor: "{colors.error-hover}"
    textColor: "{colors.on-error}"
  input-field:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.on-surface}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.sm}"
    padding: 0.35rem
    width: 340px
  input-field-border:
    backgroundColor: "{colors.outline-input}"
    height: 1px
  form-label:
    textColor: "{colors.label}"
    typography: "{typography.label-md}"
  help-text:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.muted}"
    typography: "{typography.caption}"
  table-header:
    backgroundColor: "{colors.surface-subtle}"
    textColor: "{colors.on-surface}"
    typography: "{typography.body-sm}"
    padding: 0.4rem
  table-cell:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.on-surface}"
    typography: "{typography.body-sm}"
    padding: 0.4rem
  badge-neutral:
    backgroundColor: "{colors.surface-subtle}"
    textColor: "{colors.on-surface}"
    typography: "{typography.label-sm}"
    rounded: "{rounded.full}"
  badge-success:
    backgroundColor: "{colors.success-container}"
    textColor: "{colors.on-success-container}"
    typography: "{typography.label-sm}"
    rounded: "{rounded.full}"
  badge-warning:
    backgroundColor: "{colors.warning-container}"
    textColor: "{colors.on-warning-container}"
    typography: "{typography.label-sm}"
    rounded: "{rounded.full}"
  badge-error:
    backgroundColor: "{colors.error-container}"
    textColor: "{colors.on-error-container}"
    typography: "{typography.label-sm}"
    rounded: "{rounded.full}"
  flash-success:
    backgroundColor: "{colors.success-container}"
    textColor: "{colors.on-success-container}"
    rounded: "{rounded.sm}"
    padding: 0.6rem
  flash-error:
    backgroundColor: "{colors.error-container}"
    textColor: "{colors.on-error-container}"
    rounded: "{rounded.sm}"
    padding: 0.6rem
  readonly-banner:
    backgroundColor: "{colors.surface-subtle}"
    textColor: "{colors.on-surface}"
    rounded: "{rounded.md}"
    padding: 0.5rem
  live-log:
    backgroundColor: "{colors.terminal}"
    textColor: "{colors.on-terminal}"
    typography: "{typography.data-mono}"
    rounded: "{rounded.md}"
    padding: 0.8rem
    height: 260px
  live-log-drop:
    backgroundColor: "{colors.terminal}"
    textColor: "{colors.terminal-alert}"
    typography: "{typography.data-mono}"
  live-log-meta:
    backgroundColor: "{colors.terminal}"
    textColor: "{colors.terminal-meta}"
    typography: "{typography.data-mono}"
  progress-track:
    backgroundColor: "{colors.surface-subtle}"
    rounded: "{rounded.full}"
    height: 0.9rem
  progress-fill:
    backgroundColor: "{colors.success}"
    rounded: "{rounded.full}"
---

# FR_OS Control Plane

## Overview

FR_OS is a firewall and router operating system for homelab and
small-office hardware. Its webUI is where a technically curious owner --
not necessarily a network engineer -- sees what the network is doing and
changes how it is protected. The interface should feel like **a
well-labelled instrument panel**: calm, honest and dense, never flashy.

- **Trustworthy over impressive.** Every number on screen is something the
  router actually measured; states the system can't know are shown as
  unknown ("-", "?", "not running"), never guessed. Visual confidence
  must never exceed the underlying data.
- **Explain, then act.** Each screen opens with one or two sentences of
  plain-language context (what this does, what it can't see) before the
  controls. Security features state their limits right where they are
  switched on.
- **Dense but breathable.** Tables and small type carry a lot of
  information; generous card padding and consistent vertical rhythm keep
  it readable.
- **Server-rendered and dependency-free.** No web fonts, icon fonts,
  JavaScript frameworks or CDNs: the router may have no internet access,
  and the UI must load instantly from a small device. System fonts and
  plain CSS only.
- **Audience:** the owner/administrator (full control) and read-only
  viewers (a colleague, a family member) who see everything but change
  nothing.

## Colors

A single deep navy carries the brand and every primary action; everything
else is quiet neutrals, with three semantic status colors used only to
report state.

- **Harbor Navy (#17324D, `primary`):** the header bar and every primary
  button. It signals "this is the control plane" and the one action per
  form that commits a change. Hover deepens to **#204A72**.
- **Slate (#5C6B78, `secondary`):** secondary and cancel-type buttons
  (Dry-run, Remove, Set).
- **Mist (#F2F4F6, `neutral`):** the page background behind cards.
- **Paper (#FFFFFF, `surface`)** for cards, tables and inputs, with
  **Frost (#EEF2F6, `surface-subtle`)** for table headers, neutral badges
  and the read-only banner.
- **Ink (#1A1A1A, `on-surface`)** for text, **#333333** for form labels
  and **#666677 (`muted`)** for explanations, captions and metadata.
- **Hairline (#DDE3E8, `outline`)** borders every card, table and cell;
  inputs use the slightly stronger **#C7CFD6**.
- **Status colors** always come as a trio -- a strong tone for borders
  and fills, a pale container and a dark text tone:
  - **Forest (#2F7D32)** = on / active / allowed / healthy;
  - **Amber (#B8860B)** = attention / learning / not yet active;
  - **Brick (#A83232)** = blocked / isolated / denied / destructive
    actions (Delete, Rollback). Hover brightens to **#C23D3D**.
- **Console (#0D1117 with #9BE29B text)** is reserved for live log
  streams (the XDP event log), with **#FF8A8A** for drop lines and
  **#7D8590** for meta lines.

## Typography

One family everywhere: the platform's own UI font (`system-ui`), so the
router ships no font files and every device renders it natively.

- **Page title (`headline-lg`, 1.4rem bold)** -- one per screen.
- **Card title (`headline-sm`, 1rem bold)** -- every card starts with one.
- **Body (`body-md`, 16px)** for prose; **tables, buttons and inputs use
  `body-sm` (0.88rem)** to fit dense data.
- **Form labels (`label-md`, 0.82rem semibold)** sit above their field.
- **Explanations (`caption`, 0.85rem, muted)** follow titles and sit under
  controls.
- **Badges (`label-sm`, 0.78rem)** for states.
- **Machine values -- MAC and IP addresses, fingerprints, config keys,
  service names -- are set in `data-mono`** (the platform monospace font)
  so they can be read and compared character by character.

## Layout

A single centred column, **max 980px wide** with a 1rem gutter, below a
full-width header. Content is grouped into **cards** (1rem/1.2rem padding,
1.2rem apart). A screen reads top to bottom: title → context sentence →
settings card → status card(s) → data table(s) → "add" form.

- Forms are single-column, label above field, inputs capped at 340px so
  lines stay short.
- Long tables scroll *vertically* inside their card (sticky header), never
  the whole page sideways.
- Spacing follows a small rem scale (0.2 / 0.4 / 0.6 / 1 / 1.2 / 1.5rem);
  don't invent in-between values.
- The layout must work at phone width (390px): the column simply narrows;
  tables that are too wide collapse secondary columns rather than scroll
  horizontally.

## Elevation & Depth

Flat. Hierarchy comes from **tonal layers and hairline borders**, not
shadows: Mist page → white cards with a 1px `outline` border → Frost table
headers. The only motion is the pulsing green "live" dot next to an active
log stream.

## Shapes

Soft but engineered: **4px** on buttons and inputs, **6px** on cards,
scroll containers and the log console, **fully rounded pills** for badges
and progress bars. Nothing else is rounded; icons are not used.

## Components

- **Header / navigation:** navy bar, brand "FR_OS" in bold white, links in
  #DCE7F0 turning white on hover, the signed-in user (with "(read-only)"
  for viewers) and a Logout button on the right. **Navigation is grouped**
  so it never wraps: *Network* (Interfaces, Rules, NAT, DHCP), *Protection*
  (AI IDS/IPS, TLS SNI Filter, Ad-Block, IoT Devices, Applications, TLS
  Fingerprints, ZTNA Gate) and *System* (Update, System, Users -- the last
  for admins only), plus Dashboard.
- **Buttons:** one primary (navy) per form; destructive actions in Brick
  and always behind a confirmation; secondary actions in Slate.
- **Cards:** white, hairline border, 6px radius, title first.
- **Form fields:** white inputs with a slightly darker border
  (`outline-input`) than the card hairline, labels above in `label-md`,
  help text below in `caption`, colored `muted` (#666677).
- **Tables:** full width, hairline grid, Frost header row, `body-sm` text,
  machine values in `data-mono`. Row actions (Delete, Block, Isolate) sit
  in the last column and must stay visible without horizontal scrolling.
- **Badges:** state pills -- green (on, active, trusted, allowed), amber
  (learning, not yet active, IoT), red (blocked, isolated, denied, not
  running), neutral (unknown, off). The word inside always states the
  state; color only reinforces it.
- **Flash messages:** one line under the header after every change,
  green for success, red for errors, with what happened and what to do
  next ("saved -- click Apply on the dashboard").
- **Read-only banner:** Frost strip at the top of every page for viewers.
- **Live log:** dark console card for streaming events, newest at the
  bottom, drops in light red (`terminal-alert`), timestamps and other
  metadata in grey (`terminal-meta`).
- **Secrets shown once** (a new metrics token): a success flash with the
  value in selectable monospace and the words "copy it now".

## Do's and Don'ts

- Do show the limits of a feature next to its switch ("not visible: QUIC,
  IPv6") -- honesty is part of the design.
- Do use exactly one primary button per form; Brick only for destructive
  actions, and confirm them.
- Do pair every status color with a word; never rely on color alone.
- Do keep all text contrast at WCAG AA (4.5:1) or better, including
  muted captions and badge text.
- Do render machine values (addresses, fingerprints, keys) in monospace.
- Do hide a card entirely when a viewer would see it empty; don't leave
  empty frames where forms were removed.
- Don't let the header navigation wrap onto a second line -- group it.
- Don't make tables scroll sideways; drop or merge secondary columns, or
  let long values wrap.
- Don't add web fonts, icon sets, JavaScript frameworks or external
  assets -- the UI must work offline, from the router itself.
- Don't declare `color-scheme: light dark` without dark-mode tokens:
  either design a full dark palette or keep the page light-only, so
  browser-drawn controls don't turn dark inside light cards.
- Don't put a secret (token, password) in a URL, a redirect or a log.
