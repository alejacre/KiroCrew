import { describe, it, expect, beforeEach, vi } from 'vitest'
import { screen, fireEvent, waitFor } from '@testing-library/react'

import { renderWithProviders } from './helpers'
import WebPreviewPanel from '../components/WebPreviewPanel'
import { ApiError } from '../api/apiError'

// Force the crop button's capability on (unrelated), matching the sibling suite.
vi.mock('../hooks/useScreenSnip', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../hooks/useScreenSnip')>()
  return { ...actual, isScreenSnipSupported: () => true }
})

// Stub the api seam: the browser-view status (kept `stopped` so the preview
// toolbar — where the Import cookies menu item and chip live — is the surface
// under test) and the three cookie methods. The rest of the client, including
// ApiError, stays real so the hook's status branching is exercised end to end.
const getBrowserView = vi.fn()
const startBrowserView = vi.fn()
const openInBrowser = vi.fn()
const getBrowserCookies = vi.fn()
const importBrowserCookies = vi.fn()
const clearBrowserCookies = vi.fn()
vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    api: {
      ...actual.api,
      getBrowserView: () => getBrowserView(),
      startBrowserView: () => startBrowserView(),
      openInBrowser: (url: string, sessionKey: string) => openInBrowser(url, sessionKey),
      getBrowserCookies: () => getBrowserCookies(),
      importBrowserCookies: (content: string, filename?: string) => importBrowserCookies(content, filename),
      clearBrowserCookies: () => clearBrowserCookies(),
    },
  }
})

const STOPPED = { status: 'stopped', url: null, port: null, reason: null }
const SUMMARY = {
  cookie_count: 34,
  domains: ['example.com', 'api.example.com'],
  earliest_expiry: 1_800_000_000,
  imported_at: 1_700_000_000,
}
const ABSENT = { present: false, summary: null, config_path: '/p/browser-storage-state.json' }
const PRESENT = { present: true, summary: SUMMARY, config_path: '/p/browser-storage-state.json' }

/** Open the toolbar overflow ("More actions") menu the cookie item lives in. */
function openOverflow() {
  fireEvent.pointerDown(
    screen.getByRole('button', { name: 'More actions' }),
    { pointerId: 1, button: 0, ctrlKey: false, isPrimary: true },
  )
}

beforeEach(() => {
  getBrowserView.mockReset().mockResolvedValue(STOPPED)
  startBrowserView.mockReset().mockResolvedValue(STOPPED)
  openInBrowser.mockReset()
  getBrowserCookies.mockReset().mockResolvedValue(ABSENT)
  importBrowserCookies.mockReset()
  clearBrowserCookies.mockReset()
})

describe('WebPreviewPanel — Import cookies', () => {
  it('offers Import cookies in the overflow menu', async () => {
    renderWithProviders(<WebPreviewPanel sessionKey="sess-1" />)
    await screen.findByLabelText(/preview url/i)
    openOverflow()
    expect(await screen.findByTestId('web-preview-import-cookies')).toBeTruthy()
  })

  it('opens the import dialog from the menu item', async () => {
    renderWithProviders(<WebPreviewPanel sessionKey="sess-1" />)
    await screen.findByLabelText(/preview url/i)
    openOverflow()
    fireEvent.click(await screen.findByTestId('web-preview-import-cookies'))
    expect(await screen.findByTestId('web-preview-cookies-dialog')).toBeTruthy()
    expect(screen.getByTestId('web-preview-cookies-submit')).toBeTruthy()
  })

  it('imports pasted cookies, calls the API and shows the status chip', async () => {
    importBrowserCookies.mockResolvedValue({ ok: true, summary: SUMMARY, hot_load: { loaded: ['kc-1'], failed: {} } })
    renderWithProviders(<WebPreviewPanel sessionKey="sess-1" />)
    await screen.findByLabelText(/preview url/i)
    openOverflow()
    fireEvent.click(await screen.findByTestId('web-preview-import-cookies'))
    const dialog = await screen.findByTestId('web-preview-cookies-dialog')
    const textarea = dialog.querySelector('textarea') as HTMLTextAreaElement
    fireEvent.change(textarea, { target: { value: '{"cookies":[{"name":"s","domain":"example.com"}]}' } })
    fireEvent.click(screen.getByTestId('web-preview-cookies-submit'))
    await waitFor(() => expect(importBrowserCookies).toHaveBeenCalledWith(
      '{"cookies":[{"name":"s","domain":"example.com"}]}', undefined,
    ))
    const chip = await screen.findByTestId('web-preview-cookies-chip')
    expect(chip.textContent).toContain('34')
    expect(screen.queryByTestId('web-preview-cookies-dialog')).toBeNull()
  })

  it('shows the server message inline on a 400 and keeps the dialog open', async () => {
    importBrowserCookies.mockRejectedValue(new ApiError(400, 'That is not a cookie export'))
    renderWithProviders(<WebPreviewPanel sessionKey="sess-1" />)
    await screen.findByLabelText(/preview url/i)
    openOverflow()
    fireEvent.click(await screen.findByTestId('web-preview-import-cookies'))
    const dialog = await screen.findByTestId('web-preview-cookies-dialog')
    const textarea = dialog.querySelector('textarea') as HTMLTextAreaElement
    fireEvent.change(textarea, { target: { value: 'garbage' } })
    fireEvent.click(screen.getByTestId('web-preview-cookies-submit'))
    const err = await screen.findByTestId('web-preview-cookies-error')
    expect(err.textContent).toContain('That is not a cookie export')
    expect(screen.getByTestId('web-preview-cookies-dialog')).toBeTruthy()
  })

  it('clears an imported set on the two-step Clear action', async () => {
    getBrowserCookies.mockResolvedValue(PRESENT)
    clearBrowserCookies.mockResolvedValue({ ok: true, present: false })
    renderWithProviders(<WebPreviewPanel sessionKey="sess-1" />)
    // The chip renders in the toolbar; the first web-preview-cookies-clear is it.
    const clearBtn = await screen.findByTestId('web-preview-cookies-clear')
    fireEvent.click(clearBtn) // arm
    fireEvent.click(clearBtn) // confirm
    await waitFor(() => expect(clearBrowserCookies).toHaveBeenCalled())
    await waitFor(() => expect(screen.queryByTestId('web-preview-cookies-chip')).toBeNull())
  })

  it('hides the cookie control for a non-owner (403)', async () => {
    getBrowserCookies.mockRejectedValue(new ApiError(403, 'not owner'))
    renderWithProviders(<WebPreviewPanel sessionKey="sess-1" />)
    await screen.findByLabelText(/preview url/i)
    openOverflow()
    // The overflow menu opens (Browser view item is there) but the cookie item is not.
    await screen.findByRole('menuitem', { name: /Browser view/ })
    expect(screen.queryByTestId('web-preview-import-cookies')).toBeNull()
    expect(screen.queryByTestId('web-preview-cookies-chip')).toBeNull()
  })
})
