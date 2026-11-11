// One Durable Object per teacher, in the US (Schoology's terms keep its data in the US).
// For now it only holds passkeys: public keys and counters, never a secret. Level 2's wrapped
// Schoology keys and Level 3's jobs will live here later.

import { DurableObject } from "cloudflare:workers";
import type { StoredKey } from "./webauthn.ts";

export const MAX_PASSKEYS = 10;

export interface PasskeyRow {
  id: string;
  key: StoredKey;
  signCount: number;
  name: string;
  prf: boolean;
  backedUp: boolean;
  transports: string[];
  created: number;
  lastUsed: number | null;
}

/** What the Settings list shows. No key material. */
export type PasskeySummary = Pick<PasskeyRow, "id" | "name" | "prf" | "backedUp" | "created" | "lastUsed">;

export const summary = (r: PasskeyRow): PasskeySummary => ({ id: r.id, name: r.name, prf: r.prf, backedUp: r.backedUp, created: r.created, lastUsed: r.lastUsed });

/** What routes need from a teacher's storage. The Durable Object below is the real one; tests use a Map. */
export interface PasskeyStore {
  listPasskeys(): Promise<PasskeyRow[]>;
  getPasskey(id: string): Promise<PasskeyRow | null>;
  /** False when the teacher already has MAX_PASSKEYS, or the id is taken. */
  addPasskey(row: PasskeyRow): Promise<boolean>;
  usedPasskey(id: string, signCount: number, at: number): Promise<void>;
  removePasskey(id: string): Promise<boolean>;
  removeEverything(): Promise<void>;
}

export class TeacherStore extends DurableObject implements PasskeyStore {
  private sql: SqlStorage;

  constructor(ctx: DurableObjectState, env: unknown) {
    super(ctx, env as never);
    this.sql = ctx.storage.sql;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS passkeys (
      id TEXT PRIMARY KEY,
      key TEXT NOT NULL,
      sign_count INTEGER NOT NULL,
      name TEXT NOT NULL,
      prf INTEGER NOT NULL,
      backed_up INTEGER NOT NULL,
      transports TEXT NOT NULL,
      created INTEGER NOT NULL,
      last_used INTEGER
    )`);
  }

  private row(r: Record<string, SqlStorageValue>): PasskeyRow {
    return {
      id: String(r.id),
      key: JSON.parse(String(r.key)),
      signCount: Number(r.sign_count),
      name: String(r.name),
      prf: r.prf === 1,
      backedUp: r.backed_up === 1,
      transports: JSON.parse(String(r.transports)),
      created: Number(r.created),
      lastUsed: r.last_used == null ? null : Number(r.last_used),
    };
  }

  async listPasskeys(): Promise<PasskeyRow[]> {
    return this.sql.exec("SELECT * FROM passkeys ORDER BY created").toArray().map((r) => this.row(r));
  }

  async getPasskey(id: string): Promise<PasskeyRow | null> {
    const rows = this.sql.exec("SELECT * FROM passkeys WHERE id = ?", id).toArray();
    return rows.length ? this.row(rows[0]) : null;
  }

  async addPasskey(p: PasskeyRow): Promise<boolean> {
    const n = Number(this.sql.exec("SELECT COUNT(*) AS n FROM passkeys").one().n);
    if (n >= MAX_PASSKEYS) return false;
    if (this.sql.exec("SELECT 1 FROM passkeys WHERE id = ?", p.id).toArray().length) return false;
    this.sql.exec(
      "INSERT INTO passkeys (id, key, sign_count, name, prf, backed_up, transports, created, last_used) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      p.id, JSON.stringify(p.key), p.signCount, p.name, p.prf ? 1 : 0, p.backedUp ? 1 : 0, JSON.stringify(p.transports), p.created, p.lastUsed,
    );
    return true;
  }

  async usedPasskey(id: string, signCount: number, at: number): Promise<void> {
    this.sql.exec("UPDATE passkeys SET sign_count = ?, last_used = ? WHERE id = ?", signCount, at, id);
  }

  async removePasskey(id: string): Promise<boolean> {
    return this.sql.exec("DELETE FROM passkeys WHERE id = ?", id).rowsWritten > 0;
  }

  /** Sign out everywhere, or Schoology no longer accepting the account. */
  async removeEverything(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}
