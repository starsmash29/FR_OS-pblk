---
version: alpha
name: FR_OS Control Plane
description: >-
  Visual identity of the FR_OS router webUI: a dark, dense, calm control
  plane for a firewall/router run at home or in a small office. Designed
  in the FR_OS Google Stitch project; the values below are the ones
  src/frfw/webui/static/fros.css actually uses.
colors:
  primary: "#4CD7F6"
  primary-strong: "#06B6D4"
  primary-hover: "#ACEDFF"
  on-primary: "#003640"
  primary-tint: "#122E3C"
  surface-lowest: "#070F19"
  background: "#0C141F"
  surface-low: "#141C27"
  surface: "#18202B"
  surface-high: "#232A36"
  surface-highest: "#2D3541"
  on-surface: "#DBE3F2"
  on-surface-strong: "#FFFFFF"
  on-surface-variant: "#BCC9CD"
  outline: "#869397"
  outline-variant: "#3D494C"
  hairline: "#2B353B"
  success: "#4EDEA3"
  success-container: "#1B3336"
  warning: "#F5C451"
  warning-container: "#2F302C"
  error: "#FFB4AB"
  error-strong: "#93000A"
  error-container: "#3D131E"
  on-error-container: "#FFDAD6"
  info: "#D0BCFF"
  info-container: "#272C3D"
  on-info-container: "#E9DDFF"
typography:
  headline-lg:
    fontFamily: Geist
    fontSize: 24px
    fontWeight: 600
    lineHeight: 32px
    letterSpacing: -0.015em
  headline-md:
    fontFamily: Geist
    fontSize: 18px
    fontWeight: 600
    lineHeight: 24px
    letterSpacing: -0.01em
  headline-sm:
    fontFamily: Geist
    fontSize: 15px
    fontWeight: 600
    lineHeight: 20px
  brand:
    fontFamily: Geist
    fontSize: 16px
    fontWeight: 700
    lineHeight: 20px
    letterSpacing: -0.01em
  body-md:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: 400
    lineHeight: 20px
  body-sm:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: 400
    lineHeight: 18px
  label-md:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: 600
    lineHeight: 16px
    letterSpacing: 0.05em
  label-sm:
    fontFamily: JetBrains Mono
    fontSize: 10px
    fontWeight: 600
    lineHeight: 14px
    letterSpacing: 0.08em
  metric-display:
    fontFamily: JetBrains Mono
    fontSize: 28px
    fontWeight: 700
    lineHeight: 34px
    letterSpacing: -0.03em
rounded:
  sm: 4px
  md: 8px
  lg: 12px
  full: 999px
spacing:
  topbar-height: 56px
  sidebar-width: 240px
  content-max-width: 1240px
  page-gutter: 1.5rem
  xs: 0.25rem
  sm: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.25rem
  xxl: 1.5rem
  card-padding: 1.1rem
  field-max-width: 380px
components:
  topbar:
    backgroundColor: "{colors.surface-lowest}"
    textColor: "{colors.on-surface}"
    typography: "{typography.body-sm}"
    height: 56px
  brand-mark:
    backgroundColor: "{colors.primary-tint}"
    textColor: "{colors.primary}"
    typography: "{typography.brand}"
    rounded: "{rounded.sm}"
    size: 30px
  sidebar:
    backgroundColor: "{colors.surface-lowest}"
    textColor: "{colors.on-surface-variant}"
    typography: "{typography.body-md}"
    width: 240px
  sidebar-heading:
    backgroundColor: "{colors.surface-lowest}"
    textColor: "{colors.outline}"
    typography: "{typography.label-sm}"
  nav-link-active:
    backgroundColor: "{colors.primary-tint}"
    textColor: "{colors.primary}"
    typography: "{typography.body-md}"
    rounded: "{rounded.sm}"
    padding: 0.5rem
  page:
    backgroundColor: "{colors.background}"
    textColor: "{colors.on-surface}"
    typography: "{typography.body-md}"
    width: 1240px
  page-title:
    backgroundColor: "{colors.background}"
    textColor: "{colors.on-surface-strong}"
    typography: "{typography.headline-lg}"
  card:
    backgroundColor: "{colors.surface-low}"
    textColor: "{colors.on-surface}"
    rounded: "{rounded.md}"
    padding: 1.1rem
  card-title:
    backgroundColor: "{colors.surface-low}"
    textColor: "{colors.on-surface-strong}"
    typography: "{typography.headline-sm}"
  card-border:
    backgroundColor: "{colors.hairline}"
    height: 1px
  stat-tile:
    backgroundColor: "{colors.surface-low}"
    textColor: "{colors.on-surface-strong}"
    typography: "{typography.metric-display}"
    rounded: "{rounded.md}"
    padding: 1rem
  stat-label:
    backgroundColor: "{colors.surface-low}"
    textColor: "{colors.on-surface-variant}"
    typography: "{typography.label-sm}"
  service-row:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.on-surface-strong}"
    typography: "{typography.headline-sm}"
    rounded: "{rounded.sm}"
    padding: 0.65rem
  table-header:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.on-surface-variant}"
    typography: "{typography.label-sm}"
    padding: 0.6rem
  table-cell:
    backgroundColor: "{colors.surface-low}"
    textColor: "{colors.on-surface}"
    typography: "{typography.body-sm}"
    padding: 0.6rem
  table-row-hover:
    backgroundColor: "{colors.surface-high}"
    textColor: "{colors.on-surface}"
  form-label:
    backgroundColor: "{colors.surface-low}"
    textColor: "{colors.on-surface-variant}"
    typography: "{typography.label-md}"
  input-field:
    backgroundColor: "{colors.surface-lowest}"
    textColor: "{colors.on-surface}"
    typography: "{typography.body-md}"
    rounded: "{rounded.sm}"
    padding: 0.5rem
    width: 380px
  input-border:
    backgroundColor: "{colors.outline-variant}"
    height: 1px
  input-placeholder:
    backgroundColor: "{colors.surface-lowest}"
    textColor: "{colors.outline}"
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary}"
    typography: "{typography.label-md}"
    rounded: "{rounded.sm}"
    padding: 0.5rem
    height: 34px
  button-primary-hover:
    backgroundColor: "{colors.primary-hover}"
    textColor: "{colors.on-primary}"
  button-secondary:
    backgroundColor: "{colors.surface-high}"
    textColor: "{colors.on-surface}"
    typography: "{typography.label-md}"
    rounded: "{rounded.sm}"
    padding: 0.5rem
  button-secondary-hover:
    backgroundColor: "{colors.surface-highest}"
    textColor: "{colors.on-surface-strong}"
  button-danger:
    backgroundColor: "{colors.error-container}"
    textColor: "{colors.error}"
    typography: "{typography.label-md}"
    rounded: "{rounded.sm}"
    padding: 0.5rem
  button-danger-hover:
    backgroundColor: "{colors.error-strong}"
    textColor: "{colors.on-error-container}"
  badge-neutral:
    backgroundColor: "{colors.surface-high}"
    textColor: "{colors.on-surface-variant}"
    typography: "{typography.label-sm}"
    rounded: "{rounded.sm}"
  badge-success:
    backgroundColor: "{colors.success-container}"
    textColor: "{colors.success}"
    typography: "{typography.label-sm}"
    rounded: "{rounded.sm}"
  badge-warning:
    backgroundColor: "{colors.warning-container}"
    textColor: "{colors.warning}"
    typography: "{typography.label-sm}"
    rounded: "{rounded.sm}"
  badge-error:
    backgroundColor: "{colors.error-container}"
    textColor: "{colors.error}"
    typography: "{typography.label-sm}"
    rounded: "{rounded.sm}"
  badge-accent:
    backgroundColor: "{colors.primary-tint}"
    textColor: "{colors.primary}"
    typography: "{typography.label-sm}"
    rounded: "{rounded.sm}"
  flash-success:
    backgroundColor: "{colors.success-container}"
    textColor: "{colors.on-surface-strong}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.md}"
    padding: 0.7rem
  flash-error:
    backgroundColor: "{colors.error-container}"
    textColor: "{colors.on-error-container}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.md}"
    padding: 0.7rem
  flash-warning:
    backgroundColor: "{colors.warning-container}"
    textColor: "{colors.warning}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.md}"
    padding: 0.7rem
  readonly-banner:
    backgroundColor: "{colors.info-container}"
    textColor: "{colors.on-info-container}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.md}"
    padding: 0.7rem
  readonly-icon:
    backgroundColor: "{colors.info-container}"
    textColor: "{colors.info}"
  status-dot-ok:
    backgroundColor: "{colors.success}"
    rounded: "{rounded.full}"
    size: 8px
  status-dot-off:
    backgroundColor: "{colors.outline}"
    rounded: "{rounded.full}"
    size: 8px
  progress-track:
    backgroundColor: "{colors.surface-highest}"
    rounded: "{rounded.full}"
    height: 8px
  progress-fill:
    backgroundColor: "{colors.primary-strong}"
    rounded: "{rounded.full}"
  live-log:
    backgroundColor: "{colors.surface-lowest}"
    textColor: "{colors.on-surface}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.md}"
    padding: 0.8rem
    height: 280px
  live-log-drop:
    backgroundColor: "{colors.surface-lowest}"
    textColor: "{colors.error}"
  live-log-meta:
    backgroundColor: "{colors.surface-lowest}"
    textColor: "{colors.outline}"
  auth-card:
    backgroundColor: "{colors.surface-low}"
    textColor: "{colors.on-surface}"
    rounded: "{rounded.lg}"
    padding: 2rem
  auth-accent-line:
    backgroundColor: "{colors.primary-strong}"
    height: 3px
---

# FR_OS Control Plane

## Overview

FR_OS is a firewall and router operating system for homelab and
small-office hardware. Its webUI is a **dark control plane**: navy
surfaces, one cyan accent, and a monospace body that makes addresses,
ports, MACs and fingerprints read like the machine values they are. It
should feel like a precise instrument -- modern and calm, never a
"hacker movie" -- and stay friendly for an owner who is technically
curious but not a network engineer.

The design comes from the FR_OS Google Stitch project (dark theme, Geist
and JetBrains Mono, cyan `#06B6D4` seed colour). The Stitch screens were
the reference; the webUI implements them for the features FR_OS actually
has, with real data only. Stitch screens for features that don't exist yet
are listed in ROADMAP.md, not mocked up in the product.

Principles, in priority order:

1. **True before pretty.** Every number, state and badge comes from the
   running system or the saved config. A figure that can't be read shows
   "-", never a plausible-looking placeholder.
2. **Local only.** The stylesheet, both fonts and the icon sprite are
   served by the router itself. Nothing is fetched from the internet; the
   UI works with the WAN down. No JavaScript framework; the only script is
   the live-log stream on the TLS SNI Filter screen.
3. **One accent.** Cyan marks what is interactive or current (primary
   buttons, the active nav item, links, meters). Green, amber, red and
   violet are reserved for states.
4. **Dense, not cramped.** Many facts per screen, separated by hairlines
   and consistent spacing rather than heavy boxes.

## Colors

The palette is Material-3-style tonal navy, from `surface-lowest`
(#070F19, top bar, sidebar, inputs, consoles) through `background`
(#0C141F, the page) and `surface-low` (#141C27, cards) up to
`surface-highest` (#2D3541, progress tracks, hover states).

- **Primary cyan (#4CD7F6)** -- primary buttons, links, active navigation,
  meter fills (gradient from `primary-strong` #06B6D4), focus rings.
  Text on it is `on-primary` (#003640).
- **Text** -- `on-surface` (#DBE3F2) for body, pure white for headings
  and key figures, `on-surface-variant` (#BCC9CD) for labels and help,
  `outline` (#869397) for metadata and placeholders.
- **Lines** -- `hairline` (#2B353B, the outline-variant at 55 % over a
  card) between rows and around cards; `outline-variant` (#3D494C) for
  input borders.
- **States** -- success green #4EDEA3 (running, on, accept, valid),
  warning amber #F5C451 (not yet active, reject, IoT), error salmon
  #FFB4AB on a deep red container (not running, drop, blocked, isolated,
  destructive buttons), info violet #D0BCFF (the read-only banner).
- **Containers** are the state colour at 10-32 % opacity; the hex values
  above are what they resolve to on a card.

## Typography

- **Geist** (variable, OFL) for page titles, card titles, the brand and
  service names.
- **JetBrains Mono** (variable, OFL) for everything else: body text,
  tables, forms, badges, figures. Machine values stay aligned and
  unambiguous (0/O, 1/l).
- Labels, table headers and tile captions are small uppercase mono with
  wide tracking (`label-md` / `label-sm`).
- Key figures use `metric-display`: 28px bold mono, tight tracking.
- Both fonts ship as latin + latin-ext subsets (about 100 KB in total)
  under `static/fonts/`, with their licences.

## Layout

- **Shell**: a fixed 56px top bar (brand, release chip, hostname with a
  status dot, the signed-in user and a logout button) and a fixed 240px
  sidebar with the navigation grouped as **Core** (Dashboard),
  **Network** (Interfaces, Rules, NAT, DHCP), **Protection** (AI IDS/IPS,
  TLS SNI Filter, Ad-Block, IoT Devices, Applications, TLS Fingerprints,
  ZTNA Gate) and **System** (Update, System, Users -- admins only).
- **Content**: max 1240px wide, 1.5rem gutter, starting with a
  breadcrumb (`FR_OS / Section / Page`) and the page title.
- **Dashboard**: a hero card (hostname, release, kernel, CPU, config and
  management-session state, the Apply / Dry-run / Rollback actions), a
  row of four stat tiles, then Protection services beside System
  resources, then the interface table.
- **Forms** inside cards are a two-column grid: label on the left, field
  on the right; help text, fieldsets, checkbox rows and the submit button
  span both columns. Below 700px they stack.
- **Below 900px** the sidebar becomes an off-canvas menu behind a menu
  button (CSS only); below 560px stat tiles go two per row and the user
  name hides.
- The sign-in screen is standalone: facts about the router on the left,
  the sign-in card on the right, on a faint grid with a cyan glow.

## Elevation & Depth

Depth comes from **tone, not shadow**: each layer is one step lighter
than the one below it (page -> card -> row -> hover). The only shadows
are the green glow of a live status dot and the drop shadow of the
off-canvas menu on phones. The top bar is slightly translucent with a
backdrop blur so content scrolling under it stays legible.

## Shapes

- 4px (`sm`): buttons, inputs, badges, nav items, chips.
- 8px (`md`): cards, tables, notices, consoles.
- 12px (`lg`): the sign-in card.
- Full: status dots, avatars, progress bars.

Badges are small rectangles with a 1px border in the state colour, not
pills -- they read as instrument labels.

## Components

- **Top bar / brand**: shield icon in a cyan-tinted square, "FR_OS" in
  Geist cyan, a chip with version and codename, the hostname with a green
  dot, then user avatar, name and role ("Admin" / "Read-only").
- **Sidebar**: section headings in `label-sm` outline grey; items with a
  Material Symbols icon; the current page gets the cyan tint, cyan text
  and a 2px cyan left edge.
- **Stat tile**: uppercase caption, icon in a small square, a
  `metric-display` figure (with an optional unit in cyan), one line of
  context. Tiles that correspond to a screen are links to it.
- **Service row**: status dot, name (Geist), one-line description, state
  badge. States are "running"/"not running" where a daemon can be
  checked, otherwise "on"/"off" from the config.
- **Tables**: uppercase header row on `surface`, hairline row dividers,
  hover tint, machine values in `code`. Row actions sit in the last
  column as compact buttons. A table directly on the page gets the card
  frame.
- **Buttons**: primary cyan with dark text; secondary on `surface-high`;
  danger is salmon text on a deep red container and is always behind a
  confirmation. Icons precede the label where they help (Apply, Dry-run,
  Rollback, Sign in).
- **Badges**: green / amber / red / neutral / cyan accent. The word inside
  always states the state; colour only reinforces it.
- **Notices**: success (check mark), error ("!"), warning, and the
  violet read-only banner with an eye icon. One line under the breadcrumb
  after every change, saying what happened and what to do next.
- **Meters**: label and value on one line, an 8px track with a cyan
  gradient fill.
- **Live log**: `surface-lowest` console, mono 12px, timestamps in
  outline grey, drops in salmon, a pulsing green dot while connected.
- **Icons**: Material Symbols Outlined (Apache-2.0), only the ones in use,
  compiled into `static/icons.svg` by `scripts/build-webui-icons.py`.

## Do's and Don'ts

- **Do** show real values or "-". **Don't** copy Stitch's sample figures,
  and don't add a screen for a feature that doesn't exist.
- **Do** serve every asset from the router. **Don't** link a CDN, Google
  Fonts, a remote icon font or a JS framework
  (`tests/webui/test_design_shell.py` enforces this).
- **Do** keep cyan for interaction and state colours for state. **Don't**
  use red for anything that isn't a failure, a block or a destructive
  action.
- **Do** keep text on the dark surfaces at `on-surface` or brighter;
  secondary text no dimmer than `on-surface-variant` for anything a user
  must read.
- **Do** keep row actions visible and tables inside the content width.
  **Don't** let the sidebar navigation wrap or scroll sideways.
- **Do** hide change forms from read-only viewers (the server refuses
  them anyway). **Don't** show a viewer an empty card.
- **Don't** put secrets in URLs; a new token is shown once, in the page
  body.
- **Do** add a new icon by listing it in `scripts/build-webui-icons.py`
  and rebuilding the sprite; **don't** hand-edit `icons.svg`.
