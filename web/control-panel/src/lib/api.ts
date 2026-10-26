import type { FileTransfer, UiState } from './types';

export type QrMatrix = {
  width: number;
  cells: boolean[];
};

const rawApiBase = import.meta.env.VITE_NVPN_API_BASE ?? '';
const apiBase = rawApiBase.replace(/\/+$/, '');

async function responseError(response: Response): Promise<string> {
  const contentType = response.headers.get('content-type') ?? '';
  if (contentType.includes('application/json')) {
    const body = (await response.json().catch(() => null)) as { error?: string } | null;
    if (body?.error) {
      return body.error;
    }
  }

  const text = await response.text().catch(() => '');
  return text.trim() || `${response.status} ${response.statusText}`;
}

async function postJson<T>(path: string, payload?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  const init: RequestInit = {
    method: 'POST',
    headers,
  };

  if (payload !== undefined) {
    headers['content-type'] = 'application/json';
    init.body = JSON.stringify(payload);
  }

  const response = await fetch(`${apiBase}${path}`, init);
  if (!response.ok) {
    throw new Error(await responseError(response));
  }
  return (await response.json()) as T;
}

export function tick(): Promise<UiState> {
  return postJson<UiState>('/api/tick');
}

export function runAction(endpoint: string, payload?: unknown): Promise<UiState> {
  return postJson<UiState>(endpoint, payload);
}

export function qrMatrix(text: string): Promise<QrMatrix> {
  return postJson<QrMatrix>('/api/qr_matrix', { text });
}

export async function sendFile(npub: string, file: File, signal?: AbortSignal): Promise<{ id: string }> {
  const query = new URLSearchParams({ npub, name: file.name });
  const response = await fetch(`${apiBase}/api/files/send?${query}`, {
    method: 'POST', headers: { 'content-type': 'application/octet-stream' }, body: file, signal,
  });
  if (!response.ok) throw new Error(await responseError(response));
  return response.json();
}

export function fileAction(id: string, action: 'accept' | 'decline' | 'cancel' | 'resume'): Promise<unknown> {
  return postJson(`/api/files/${encodeURIComponent(id)}/${action}`);
}

export function fileDownloadUrl(id: string, index: number): string {
  return `${apiBase}/api/files/${encodeURIComponent(id)}/${index}`;
}

export async function fileHistory(before?: string): Promise<{ transfers: FileTransfer[]; nextCursor: string | null }> {
  const query = before ? `?${new URLSearchParams({ before })}` : '';
  const response = await fetch(`${apiBase}/api/files${query}`);
  if (!response.ok) throw new Error(await responseError(response));
  return response.json();
}
