import { useCallback, useEffect, useId, useRef, useState } from 'react'
import { Cookie, Upload, X, Loader2, AlertTriangle, Check } from 'lucide-react'

import { ApiError } from '../api/apiError'
import { fmtNumber, fmtRelative } from '../i18n/format'
import { i18nT } from '../i18n/t'
import type { useBrowserCookies } from '../hooks/useBrowserCookies'
import { DropdownMenuItem } from './ui/dropdown-menu'
import { Btn } from './ui'

/** The shared shape returned by `useBrowserCookies`, passed to each piece so the
 * panel holds ONE hook instance (one status read, one dialog) while the trigger,
 * chip and dialog render in their own places. */
type Cookies = ReturnType<typeof useBrowserCookies>

/** How many domains the status-chip tooltip lists before it caps with "+N more". */
const DOMAIN_TOOLTIP_CAP = 15

/** Extract the user-readable message from a failed import. `friendlyErrText`
 * (in the api layer) already unwraps a `{"error": "…"}` 400 body into
 * `ApiError.message`, so the message is the thing to show inline. */
function importErrorText(e: unknown): string {
  if (e instanceof ApiError && e.message) return e.message
  if (e instanceof Error && e.message) return e.message
  return i18nT('components.webPreviewPanel.cookies_import_failed_generic')
}

/** The domain tooltip: distinct domains, capped, with a localized "+N more". */
function domainsTooltip(domains: string[]): string {
  if (domains.length <= DOMAIN_TOOLTIP_CAP) return domains.join('\n')
  const shown = domains.slice(0, DOMAIN_TOOLTIP_CAP)
  const rest = domains.length - DOMAIN_TOOLTIP_CAP
  return `${shown.join('\n')}\n${i18nT('components.webPreviewPanel.cookies_domains_more', { count: fmtNumber(rest) })}`
}

/** The full chip line: "34 cookies · 12 sites · expires in 19h". Counts follow
 * the active locale (fmtNumber); the expiry is a relative time (fmtRelative),
 * omitted when every cookie is session-scoped. */
function cookieChipText(summary: {
  cookie_count: number
  domains: string[]
  earliest_expiry: number | null
}): string {
  const parts = [
    i18nT('components.webPreviewPanel.cookies_count', { count: fmtNumber(summary.cookie_count) }),
    i18nT('components.webPreviewPanel.cookies_sites', { count: fmtNumber(summary.domains.length) }),
  ]
  if (summary.earliest_expiry != null) {
    parts.push(i18nT('components.webPreviewPanel.cookies_expires', {
      when: fmtRelative(summary.earliest_expiry),
    }))
  }
  return parts.join(' · ')
}

/**
 * The overflow-menu entry that opens the import dialog. Lives INSIDE the preview
 * toolbar's existing "More actions" dropdown rather than as another toolbar
 * button, so the row's sibling-button count (guarded for the
 * max-two-buttons-per-row rule) does not grow. Hidden for a non-owner.
 */
export function CookieMenuItem({ cookies, onOpen }: { cookies: Cookies; onOpen: () => void }) {
  if (cookies.forbidden) return null
  return (
    <DropdownMenuItem onSelect={onOpen} data-testid="web-preview-import-cookies">
      <Cookie size={13} className="shrink-0 text-muted" />
      <span>{i18nT('components.webPreviewPanel.import_cookies')}</span>
    </DropdownMenuItem>
  )
}

/**
 * The header button that opens the import dialog — for the browser-view overlay
 * header, which has no sibling-button-count guard (unlike the preview toolbar).
 * Hidden for a non-owner.
 */
export function CookieHeaderButton({ cookies, onOpen }: { cookies: Cookies; onOpen: () => void }) {
  if (cookies.forbidden) return null
  return (
    <button
      type="button"
      onClick={onOpen}
      className="flex items-center justify-center w-6 h-6 rounded text-muted hover:text-text hover:bg-bg-hover transition-colors bg-transparent border-none cursor-pointer shrink-0"
      title={i18nT('components.webPreviewPanel.import_cookies')}
      aria-label={i18nT('components.webPreviewPanel.import_cookies')}
      data-testid="web-preview-import-cookies-btn"
    >
      <Cookie size={14} />
    </button>
  )
}

/**
 * The status chip: "34 cookies · 12 sites · expires in 19h" with a domain
 * tooltip and a two-step Clear. Shown only when a set is imported. `compact`
 * drops the text to just the count for the tight overlay header (full detail
 * stays in the tooltip). Hidden for a non-owner or when nothing is imported.
 */
export function CookieChip({ cookies, compact = false }: { cookies: Cookies; compact?: boolean }) {
  const [clearArmed, setClearArmed] = useState(false)
  const clearTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const summary = cookies.data?.summary ?? null

  const armClear = useCallback(() => {
    if (clearArmed) {
      if (clearTimer.current) clearTimeout(clearTimer.current)
      setClearArmed(false)
      void cookies.clear().catch(() => { /* surfaced via clearError */ })
      return
    }
    setClearArmed(true)
    clearTimer.current = setTimeout(() => setClearArmed(false), 3000)
  }, [clearArmed, cookies])

  if (cookies.forbidden || !cookies.data?.present || !summary) return null

  const label = compact
    ? i18nT('components.webPreviewPanel.cookies_chip_compact', { count: fmtNumber(summary.cookie_count) })
    : cookieChipText(summary)

  return (
    <span
      className="inline-flex items-center gap-1 shrink min-w-0 max-w-[240px] h-6 pl-1.5 pr-0.5 rounded-md bg-bg-elevated border border-border text-[11px] text-muted"
      data-testid="web-preview-cookies-chip"
      title={domainsTooltip(summary.domains)}
    >
      <Cookie size={11} className="shrink-0 text-accent" aria-hidden />
      <span className="truncate">{label}</span>
      <Btn
        aria-label={clearArmed
          ? i18nT('components.webPreviewPanel.cookies_clear_confirm')
          : i18nT('components.webPreviewPanel.cookies_clear')}
        title={clearArmed
          ? i18nT('components.webPreviewPanel.cookies_clear_confirm')
          : i18nT('components.webPreviewPanel.cookies_clear')}
        onClick={armClear}
        disabled={cookies.clearing}
        className={`shrink-0 ${clearArmed ? 'text-danger' : ''}`}
        data-testid="web-preview-cookies-clear"
      >
        {cookies.clearing
          ? <Loader2 className="lucide-inline animate-spin" />
          : <X className="lucide-inline" />}
      </Btn>
    </span>
  )
}

/**
 * The "applies to new sessions" hint, shown after a successful import that
 * reached no live browser session while the view is running.
 */
export function CookieNewSessionHint({ show }: { show: boolean }) {
  if (!show) return null
  return (
    <span
      className="inline-flex items-center gap-1 shrink-0 text-[11px] text-muted"
      data-testid="web-preview-cookies-new-session-hint"
    >
      <Check size={11} className="shrink-0 text-accent" aria-hidden />
      {i18nT('components.webPreviewPanel.cookies_apply_to_new_sessions')}
    </span>
  )
}

/**
 * The import dialog: explanation, file picker (.json/.txt via FileReader), paste
 * textarea, Import/Cancel. Rendered ONCE by the panel as a fixed overlay so it
 * shows over either header. `open` is controlled by the panel; `onDone` reports
 * whether the successful import reached no live session (so the panel can show
 * the new-session hint). A 400 is shown inline and keeps the dialog open.
 */
export function CookieDialog({
  cookies,
  viewRunning,
  open,
  onClose,
  onImported,
}: {
  cookies: Cookies
  viewRunning: boolean
  open: boolean
  onClose: () => void
  onImported: (reachedNewSessionsOnly: boolean) => void
}) {
  const [paste, setPaste] = useState('')
  const [filename, setFilename] = useState<string | undefined>(undefined)
  const [inlineError, setInlineError] = useState<string | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const dialogTitleId = useId()

  const reset = useCallback(() => {
    setPaste('')
    setFilename(undefined)
    setInlineError(null)
    if (fileRef.current) fileRef.current.value = ''
  }, [])

  const close = useCallback(() => { reset(); onClose() }, [reset, onClose])

  // Esc closes the dialog. A document listener rather than a handler on the
  // overlay keeps the backdrop free of keyboard handlers (a11y) and works
  // regardless of where focus sits inside the card.
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') close() }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open, close])

  const onFile = useCallback((file: File) => {
    const reader = new FileReader()
    reader.onload = () => {
      setPaste(typeof reader.result === 'string' ? reader.result : '')
      setFilename(file.name)
      setInlineError(null)
    }
    reader.onerror = () => setInlineError(i18nT('components.webPreviewPanel.cookies_file_read_failed'))
    reader.readAsText(file)
  }, [])

  const submit = useCallback(async () => {
    const content = paste.trim()
    if (!content) {
      setInlineError(i18nT('components.webPreviewPanel.cookies_paste_or_choose_a_file'))
      return
    }
    setInlineError(null)
    try {
      const result = await cookies.importCookies(content, filename)
      const reachedNone = result.hot_load.loaded.length === 0
      onImported(viewRunning && reachedNone)
      close()
    } catch (e) {
      // A 400 (malformed input) is shown inline; the dialog stays open so the
      // user can fix the paste and retry.
      setInlineError(importErrorText(e))
    }
  }, [paste, filename, cookies, viewRunning, onImported, close])

  if (!open) return null

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby={dialogTitleId}
      data-testid="web-preview-cookies-dialog"
    >
      {/* A real button behind the card carries the backdrop-dismiss, so the
          gesture is keyboard-reachable without hanging handlers on a div. */}
      <button
        type="button"
        aria-label={i18nT('components.webPreviewPanel.cookies_cancel')}
        tabIndex={-1}
        className="absolute inset-0 w-full h-full bg-transparent border-none cursor-default"
        onClick={close}
      />
      <div className="relative w-full max-w-[460px] rounded-lg border border-border bg-bg shadow-lg overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-border">
          <Cookie size={15} className="shrink-0 text-accent" aria-hidden />
          <span id={dialogTitleId} className="text-[13px] font-medium text-text">
            {i18nT('components.webPreviewPanel.import_cookies')}
          </span>
          <div className="flex-1" />
          <Btn aria-label={i18nT('app.dismiss')} onClick={close} className="shrink-0">
            <X className="lucide-inline" />
          </Btn>
        </div>

        <div className="px-4 py-3 flex flex-col gap-3">
          <p className="text-[12px] text-muted leading-snug m-0">
            {i18nT('components.webPreviewPanel.cookies_dialog_explanation')}
          </p>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => fileRef.current?.click()}
              className="inline-flex items-center gap-1.5 text-[12px] px-3 py-1.5 rounded-md border border-border text-text hover:bg-bg-hover transition-colors cursor-pointer bg-transparent"
            >
              <Upload size={13} /> {i18nT('components.webPreviewPanel.cookies_choose_a_file')}
            </button>
            {filename && (
              <span className="text-[11px] text-muted truncate min-w-0" title={filename}>{filename}</span>
            )}
            <input
              ref={fileRef}
              type="file"
              accept=".json,.txt,application/json,text/plain"
              className="sr-only"
              aria-label={i18nT('components.webPreviewPanel.cookies_choose_a_file')}
              onChange={(e) => {
                const file = e.target.files?.[0]
                e.target.value = ''
                if (file) onFile(file)
              }}
            />
          </div>

          <textarea
            value={paste}
            onChange={(e) => { setPaste(e.target.value); setFilename(undefined); setInlineError(null) }}
            placeholder={i18nT('components.webPreviewPanel.cookies_paste_placeholder')}
            aria-label={i18nT('components.webPreviewPanel.cookies_paste_label')}
            spellCheck={false}
            rows={6}
            className="w-full resize-y rounded-md border border-border bg-bg-elevated text-[12px] font-mono text-text placeholder:text-muted px-2 py-1.5 focus:border-accent outline-none"
          />

          {inlineError && (
            <div
              className="flex items-start gap-1.5 text-[11px] leading-snug text-danger"
              data-testid="web-preview-cookies-error"
              role="alert"
            >
              <AlertTriangle size={13} className="shrink-0 mt-0.5" aria-hidden />
              <span className="min-w-0">{inlineError}</span>
            </div>
          )}
        </div>

        <div className="flex items-center justify-end gap-2 px-4 py-3 border-t border-border">
          <button
            type="button"
            onClick={close}
            className="text-[12px] px-3 py-1.5 rounded-md border border-border text-muted hover:text-text hover:bg-bg-hover transition-colors cursor-pointer bg-transparent"
          >
            {i18nT('components.webPreviewPanel.cookies_cancel')}
          </button>
          <button
            type="button"
            onClick={() => { void submit() }}
            disabled={cookies.importing}
            className="inline-flex items-center gap-1.5 text-[12px] px-3 py-1.5 rounded-md bg-accent text-white hover:opacity-90 transition-opacity cursor-pointer border-none disabled:opacity-60 disabled:cursor-default"
            data-testid="web-preview-cookies-submit"
          >
            {cookies.importing ? <Loader2 size={13} className="animate-spin" /> : <Upload size={13} />}
            {i18nT('components.webPreviewPanel.cookies_import_action')}
          </button>
        </div>
      </div>
    </div>
  )
}
