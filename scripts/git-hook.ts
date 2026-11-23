#!/usr/bin/env bun
/**
 * Canonical Git hook and privacy check for every sakuragaoka-homelab repository.
 *
 * This file is kept byte-identical in every repository. It must not embed a
 * directory depth: the repository root comes from `git rev-parse
 * --show-toplevel`, so the same bytes work in every checkout.
 *
 * Usage:
 *   bun scripts/git-hook.ts pre-commit
 *   bun scripts/git-hook.ts pre-push
 *   bun scripts/git-hook.ts privacy-identity
 *   bun scripts/git-hook.ts privacy [--root DIR]
 *   bun scripts/git-hook.ts privacy-staged [--root DIR]
 *   bun scripts/git-hook.ts privacy-range REV BASE
 *   bun scripts/git-hook.ts privacy-commits REV
 *   bun scripts/git-hook.ts whitespace | whitespace-staged
 *   bun scripts/git-hook.ts gitleaks [RANGE]
 *   bun scripts/git-hook.ts agent-files
 *   bun scripts/git-hook.ts history
 *   bun scripts/git-hook.ts inspect
 *
 * `pre-push` refuses `refs/heads/main`, refuses commits a push would publish
 * without a good signature, then scans the exact pushed range.
 *
 * Exit codes: 0 passed, 1 review required, 2 the check could not complete.
 * Matched values and filenames are never printed; only detection labels.
 *
 * Optional private denylist: OWNER_PRIVACY_TERMS_FILE (legacy
 * AGENT_TOOLING_PRIVACY_TERMS) names a file with one case-insensitive term per
 * line. The owner's account usernames stay allowed as plain words.
 */
import { spawnSync } from "node:child_process";
import {
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  statSync,
  type Stats,
} from "node:fs";
import { basename, join } from "node:path";

export const MAX_BYTES = 1024 * 1024;
const TERMS_VARIABLES = [
  "OWNER_PRIVACY_TERMS_FILE",
  "AGENT_TOOLING_PRIVACY_TERMS",
  "SERVER_PRIVACY_TERMS_FILE",
] as const;

/**
 * The owner's GitHub/Copilot account usernames are public by owner decision.
 * They stay allowed as plain words even when a private denylist names them.
 * Account emails, tokens, keys, addresses and hostnames remain private.
 */
const ALLOWED_ACCOUNT_NAMES = new Set(["deathpie", "simpsonm09"]);
const EMPTY = new Uint8Array(0);
const COMMIT_MESSAGE_NAME = new Uint8Array(
  Buffer.from("commit-message", "utf8"),
);

/** Python `\w` for `str` patterns: Unicode letters, numbers and underscore. */
const WORD = String.raw`\p{L}\p{N}_`;
/** Python `\d` for `str` patterns. */
const DIGIT = String.raw`\p{Nd}`;
/** Hex digits as matched by `[\da-f]` under `re.I`. */
const HEX = String.raw`\p{Nd}a-f`;
/** Python `\s` for `str` patterns. JavaScript `\s` differs at `\x1c-\x1f` and `\ufeff`. */
const WS = String.raw`\t\n\v\f\r \x1c-\x1f\x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000`;
/** Python `\b` where the adjacent pattern character is a word character. */
const BEFORE_WORD = `(?<![${WORD}])`;
const AFTER_WORD = `(?![${WORD}])`;
/** Python `^` in `re.MULTILINE` mode: start of input or straight after `\n`. */
const LINE_START = String.raw`(?:^|(?<=\n))`;

const RULES: ReadonlyArray<readonly [label: string, pattern: RegExp]> = [
  [
    "personal home path",
    new RegExp(`(?<![${WORD}.-])/(?:var/)?home/[^/$<>${WS}]+`, "iu"),
  ],
  [
    "personal home path",
    new RegExp(
      String.raw`[A-Za-z]:\\+Users\\+` +
        `(?!<|\\$|person${AFTER_WORD}|example${AFTER_WORD}|user${AFTER_WORD}|username${AFTER_WORD}|you${AFTER_WORD}|Public${AFTER_WORD}|Default${AFTER_WORD}|Shared${AFTER_WORD})` +
        `[${WORD}.-]+`,
      "iu",
    ),
  ],
  [
    "personal home path",
    new RegExp(
      `(?:^|[^${WORD}.-])/` +
        `Users/` +
        `(?!<|\\$|Shared${AFTER_WORD}|person${AFTER_WORD}|example${AFTER_WORD}|user${AFTER_WORD}|username${AFTER_WORD}|you${AFTER_WORD}|Public${AFTER_WORD}|Default${AFTER_WORD})` +
        `[${WORD}.-]+`,
      "iu",
    ),
  ],
  [
    "filesystem identifier",
    new RegExp(
      `${BEFORE_WORD}[${HEX}]{8}(?:-[${HEX}]{4}){3}-[${HEX}]{12}${AFTER_WORD}`,
      "iu",
    ),
  ],
  ["email address", new RegExp(`[${WORD}.+-]+@[${WORD}.-]+\\.[a-z]{2,}`, "iu")],
  [
    "tailnet DNS name",
    new RegExp(`[${WORD}.-]+\\.ts\\.net${AFTER_WORD}`, "iu"),
  ],
  [
    "hardware address",
    new RegExp(
      `${BEFORE_WORD}(?:[${HEX}]{2}:){5}[${HEX}]{2}${AFTER_WORD}`,
      "iu",
    ),
  ],
  [
    "provider credential",
    new RegExp(
      `${BEFORE_WORD}(?:gh[pousr]_|github_pat_|sk-(?:ant-|proj-)?|AIza|xox[baprs]-|tskey-|AGE-SECRET-KEY-1)[${WORD}-]{16,}`,
      "iu",
    ),
  ],
  [
    "private key",
    new RegExp(String.raw`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----`, "iu"),
  ],
  [
    "credential assignment",
    new RegExp(
      `${LINE_START}[ \t]*(?:export[ \t]+)?["']?[${WORD}-]*(?:password|passwd|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|management[_-]?key|secret[_-]?key)` +
        `(?!_(?:file|path|dir|url)${AFTER_WORD})` +
        `[${WORD}-]*["']?[ \t]*[:=][ \t]*["']?` +
        `(?!<|\\$|\\{|YOUR_|PLACEHOLDER)` +
        `(?=[A-Za-z0-9_+/=.-]*\\d)(?=[A-Za-z0-9_+/=.-]*[A-Za-z])` +
        `[A-Za-z0-9_+/=.-]{16,}`,
      "iu",
    ),
  ],
  ["bcrypt hash", /\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}/u],
  ["argon2 hash", /\$argon2(?:id|i|d)\$[^\s"'<>]{8,}/u],
  ["bearer token", /Authorization:\s*Bearer\s+(?!<|\$)[A-Za-z0-9._~+/-]{16,}/u],
  [
    "JSON web token",
    /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/u,
  ],
  [
    "assigned hex token",
    /(?<![A-Za-z0-9_-])["']?[A-Za-z0-9_-]*(?:token|key|secret|password|auth)[A-Za-z0-9_-]*["']?[ \t]*[:=][ \t]*["']?[0-9a-f]{40}(?:[0-9a-f]{24})?(?![0-9a-f])/u,
  ],
  [
    "hardware serial",
    new RegExp(
      `${LINE_START}[${WS}]*(?:serial(?:[${WS}]+number)?|wwn|machine-id)[${WS}]*[:=][${WS}]*` +
        `(?!number${AFTER_WORD}|string${AFTER_WORD}|boolean${AFTER_WORD}|unknown${AFTER_WORD}|any${AFTER_WORD}|never${AFTER_WORD}|object${AFTER_WORD}|bigint${AFTER_WORD}|symbol${AFTER_WORD}|undefined${AFTER_WORD}|null${AFTER_WORD}|void${AFTER_WORD})` +
        `[^<$` +
        WS +
        `][${WORD}-]{5,}(?![${WORD}.-])`,
      "iu",
    ),
  ],
];

const ADDRESS = new RegExp(
  `(?<![${WORD}.])(?:[${DIGIT}]{1,3}\\.){3}[${DIGIT}]{1,3}(?![${WORD}.])`,
  "giu",
);
const IPV6 = new RegExp(
  `(?<![${WORD}:])(?:[${DIGIT}a-f]{0,4}:){2,}[${DIGIT}a-f:]{0,4}(?:%[${WORD}.-]+)?(?![${WORD}:])`,
  "giu",
);

const GITHUB_NOREPLY = new RegExp(
  `^(?:[0-9]+\\+)?[a-z0-9-]+(?:\\[bot\\])?@users\\.noreply\\.github\\.com$`,
  "iu",
);
const IDENTITY = new RegExp(
  String.raw`^[^\n]+ <([^<>]+)> [0-9]+ [+-][0-9]{4}$`,
  "u",
);

/**
 * Vendor no-reply addresses that may appear in a commit-message trailer. They
 * identify a service, not a person, so a commit message may mention them while
 * file content still may not contain any address. The list is deliberately
 * short: Anthropic's and GitHub's service mailboxes (including the address
 * Dependabot signs off with) plus GitHub's `users.noreply.github.com` aliases
 * (already allowed for commit identities). Lookarounds keep a lookalike domain
 * from being stripped with the real one.
 */
const VENDOR_COMMIT_NOREPLY = new RegExp(
  `(?<![${WORD}.+-])(?:` +
    `(?:noreply|support)@(?:anthropic|github)\\.com` +
    `|(?:[0-9]+\\+)?[a-z0-9-]+(?:\\[bot\\])?@users\\.noreply\\.github\\.com` +
    `)(?![${WORD}.-])`,
  "giu",
);

const SERVICE_EMAIL = "noreply@" + "github.com";
const CREDENTIAL_BASENAMES = new Set([
  "auth.json",
  "credentials.json",
  "id_rsa",
  "id_ed25519",
]);
const CREDENTIAL_SUFFIXES = [".key", ".pem", ".p12", ".pfx"];

/**
 * Code points where Python `str.casefold()` differs from the lowercase mapping
 * used by JavaScript. One entry per line, source and target separated by a tab.
 * Targets may expand to more than one code point.
 */
const CASEFOLD_PAIRS = `µ	μ
ß	ss
ŉ	ʼn
ſ	s
ǰ	ǰ
ͅ	ι
ΐ	ΐ
ΰ	ΰ
ς	σ
ϐ	β
ϑ	θ
ϕ	φ
ϖ	π
ϰ	κ
ϱ	ρ
ϵ	ε
և	եւ
Ꭰ	Ꭰ
Ꭱ	Ꭱ
Ꭲ	Ꭲ
Ꭳ	Ꭳ
Ꭴ	Ꭴ
Ꭵ	Ꭵ
Ꭶ	Ꭶ
Ꭷ	Ꭷ
Ꭸ	Ꭸ
Ꭹ	Ꭹ
Ꭺ	Ꭺ
Ꭻ	Ꭻ
Ꭼ	Ꭼ
Ꭽ	Ꭽ
Ꭾ	Ꭾ
Ꭿ	Ꭿ
Ꮀ	Ꮀ
Ꮁ	Ꮁ
Ꮂ	Ꮂ
Ꮃ	Ꮃ
Ꮄ	Ꮄ
Ꮅ	Ꮅ
Ꮆ	Ꮆ
Ꮇ	Ꮇ
Ꮈ	Ꮈ
Ꮉ	Ꮉ
Ꮊ	Ꮊ
Ꮋ	Ꮋ
Ꮌ	Ꮌ
Ꮍ	Ꮍ
Ꮎ	Ꮎ
Ꮏ	Ꮏ
Ꮐ	Ꮐ
Ꮑ	Ꮑ
Ꮒ	Ꮒ
Ꮓ	Ꮓ
Ꮔ	Ꮔ
Ꮕ	Ꮕ
Ꮖ	Ꮖ
Ꮗ	Ꮗ
Ꮘ	Ꮘ
Ꮙ	Ꮙ
Ꮚ	Ꮚ
Ꮛ	Ꮛ
Ꮜ	Ꮜ
Ꮝ	Ꮝ
Ꮞ	Ꮞ
Ꮟ	Ꮟ
Ꮠ	Ꮠ
Ꮡ	Ꮡ
Ꮢ	Ꮢ
Ꮣ	Ꮣ
Ꮤ	Ꮤ
Ꮥ	Ꮥ
Ꮦ	Ꮦ
Ꮧ	Ꮧ
Ꮨ	Ꮨ
Ꮩ	Ꮩ
Ꮪ	Ꮪ
Ꮫ	Ꮫ
Ꮬ	Ꮬ
Ꮭ	Ꮭ
Ꮮ	Ꮮ
Ꮯ	Ꮯ
Ꮰ	Ꮰ
Ꮱ	Ꮱ
Ꮲ	Ꮲ
Ꮳ	Ꮳ
Ꮴ	Ꮴ
Ꮵ	Ꮵ
Ꮶ	Ꮶ
Ꮷ	Ꮷ
Ꮸ	Ꮸ
Ꮹ	Ꮹ
Ꮺ	Ꮺ
Ꮻ	Ꮻ
Ꮼ	Ꮼ
Ꮽ	Ꮽ
Ꮾ	Ꮾ
Ꮿ	Ꮿ
Ᏸ	Ᏸ
Ᏹ	Ᏹ
Ᏺ	Ᏺ
Ᏻ	Ᏻ
Ᏼ	Ᏼ
Ᏽ	Ᏽ
ᏸ	Ᏸ
ᏹ	Ᏹ
ᏺ	Ᏺ
ᏻ	Ᏻ
ᏼ	Ᏼ
ᏽ	Ᏽ
ᲀ	в
ᲁ	д
ᲂ	о
ᲃ	с
ᲄ	т
ᲅ	т
ᲆ	ъ
ᲇ	ѣ
ᲈ	ꙋ
ẖ	ẖ
ẗ	ẗ
ẘ	ẘ
ẙ	ẙ
ẚ	aʾ
ẛ	ṡ
ẞ	ss
ὐ	ὐ
ὒ	ὒ
ὔ	ὔ
ὖ	ὖ
ᾀ	ἀι
ᾁ	ἁι
ᾂ	ἂι
ᾃ	ἃι
ᾄ	ἄι
ᾅ	ἅι
ᾆ	ἆι
ᾇ	ἇι
ᾈ	ἀι
ᾉ	ἁι
ᾊ	ἂι
ᾋ	ἃι
ᾌ	ἄι
ᾍ	ἅι
ᾎ	ἆι
ᾏ	ἇι
ᾐ	ἠι
ᾑ	ἡι
ᾒ	ἢι
ᾓ	ἣι
ᾔ	ἤι
ᾕ	ἥι
ᾖ	ἦι
ᾗ	ἧι
ᾘ	ἠι
ᾙ	ἡι
ᾚ	ἢι
ᾛ	ἣι
ᾜ	ἤι
ᾝ	ἥι
ᾞ	ἦι
ᾟ	ἧι
ᾠ	ὠι
ᾡ	ὡι
ᾢ	ὢι
ᾣ	ὣι
ᾤ	ὤι
ᾥ	ὥι
ᾦ	ὦι
ᾧ	ὧι
ᾨ	ὠι
ᾩ	ὡι
ᾪ	ὢι
ᾫ	ὣι
ᾬ	ὤι
ᾭ	ὥι
ᾮ	ὦι
ᾯ	ὧι
ᾲ	ὰι
ᾳ	αι
ᾴ	άι
ᾶ	ᾶ
ᾷ	ᾶι
ᾼ	αι
ι	ι
ῂ	ὴι
ῃ	ηι
ῄ	ήι
ῆ	ῆ
ῇ	ῆι
ῌ	ηι
ῒ	ῒ
ΐ	ΐ
ῖ	ῖ
ῗ	ῗ
ῢ	ῢ
ΰ	ΰ
ῤ	ῤ
ῦ	ῦ
ῧ	ῧ
ῲ	ὼι
ῳ	ωι
ῴ	ώι
ῶ	ῶ
ῷ	ῶι
ῼ	ωι
ꭰ	Ꭰ
ꭱ	Ꭱ
ꭲ	Ꭲ
ꭳ	Ꭳ
ꭴ	Ꭴ
ꭵ	Ꭵ
ꭶ	Ꭶ
ꭷ	Ꭷ
ꭸ	Ꭸ
ꭹ	Ꭹ
ꭺ	Ꭺ
ꭻ	Ꭻ
ꭼ	Ꭼ
ꭽ	Ꭽ
ꭾ	Ꭾ
ꭿ	Ꭿ
ꮀ	Ꮀ
ꮁ	Ꮁ
ꮂ	Ꮂ
ꮃ	Ꮃ
ꮄ	Ꮄ
ꮅ	Ꮅ
ꮆ	Ꮆ
ꮇ	Ꮇ
ꮈ	Ꮈ
ꮉ	Ꮉ
ꮊ	Ꮊ
ꮋ	Ꮋ
ꮌ	Ꮌ
ꮍ	Ꮍ
ꮎ	Ꮎ
ꮏ	Ꮏ
ꮐ	Ꮐ
ꮑ	Ꮑ
ꮒ	Ꮒ
ꮓ	Ꮓ
ꮔ	Ꮔ
ꮕ	Ꮕ
ꮖ	Ꮖ
ꮗ	Ꮗ
ꮘ	Ꮘ
ꮙ	Ꮙ
ꮚ	Ꮚ
ꮛ	Ꮛ
ꮜ	Ꮜ
ꮝ	Ꮝ
ꮞ	Ꮞ
ꮟ	Ꮟ
ꮠ	Ꮠ
ꮡ	Ꮡ
ꮢ	Ꮢ
ꮣ	Ꮣ
ꮤ	Ꮤ
ꮥ	Ꮥ
ꮦ	Ꮦ
ꮧ	Ꮧ
ꮨ	Ꮨ
ꮩ	Ꮩ
ꮪ	Ꮪ
ꮫ	Ꮫ
ꮬ	Ꮬ
ꮭ	Ꮭ
ꮮ	Ꮮ
ꮯ	Ꮯ
ꮰ	Ꮰ
ꮱ	Ꮱ
ꮲ	Ꮲ
ꮳ	Ꮳ
ꮴ	Ꮴ
ꮵ	Ꮵ
ꮶ	Ꮶ
ꮷ	Ꮷ
ꮸ	Ꮸ
ꮹ	Ꮹ
ꮺ	Ꮺ
ꮻ	Ꮻ
ꮼ	Ꮼ
ꮽ	Ꮽ
ꮾ	Ꮾ
ꮿ	Ꮿ
ﬀ	ff
ﬁ	fi
ﬂ	fl
ﬃ	ffi
ﬄ	ffl
ﬅ	st
ﬆ	st
ﬓ	մն
ﬔ	մե
ﬕ	մի
ﬖ	վն
ﬗ	մխ`;

const CASEFOLD = (() => {
  const table = new Map<string, string>();
  for (const line of CASEFOLD_PAIRS.split("\n")) {
    if (line.length === 0) continue;
    const [from, to] = line.split("\t");
    if (from !== undefined && to !== undefined) table.set(from, to);
  }
  return table;
})();

const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const PY_STRIP = new RegExp(`^[${WS}]+|[${WS}]+$`, "gu");
const PY_LINE_BREAK = new RegExp(
  String.raw`\r\n|[\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029]`,
  "gu",
);
const ASCII_WHITESPACE = /[\t\n\v\f\r ]+/u;
const UNICODE_DIGIT = /^\p{Nd}$/u;

export interface AddressInfo {
  version: 4 | 6;
  loopback: boolean;
  unspecified: boolean;
}

export interface Options {
  staged: boolean;
  history: boolean;
  range: string[] | null;
  identity: boolean;
  root: string;
}

export class UsageError extends Error {}

export class HelpRequested extends Error {}

/** Python `os.fsdecode` equivalent, good enough for lowercased basenames. */
function looseDecode(data: Uint8Array): string {
  return Buffer.from(data).toString("utf8");
}

/** Strict UTF-8 decode; `null` where Python raises `UnicodeDecodeError`. */
function decodeUtf8(data: Uint8Array): string | null {
  try {
    return UTF8.decode(data);
  } catch {
    return null;
  }
}

function decodeText(data: Uint8Array): string {
  const text = decodeUtf8(data);
  if (text === null) throw new Error("invalid UTF-8");
  return text;
}

/** Python `str.strip()`: its whitespace set differs from JavaScript's `\s`. */
export function pyStrip(value: string): string {
  return value.replace(PY_STRIP, "");
}

/** Python `str.splitlines()`, which drops a trailing empty field. */
export function splitLines(value: string): string[] {
  const out: string[] = [];
  if (value.length === 0) return out;
  PY_LINE_BREAK.lastIndex = 0;
  let last = 0;
  for (
    let match = PY_LINE_BREAK.exec(value);
    match !== null;
    match = PY_LINE_BREAK.exec(value)
  ) {
    out.push(value.slice(last, match.index));
    last = match.index + match[0].length;
  }
  if (last < value.length) out.push(value.slice(last));
  return out;
}

/** Python `str.casefold()` via the lowercase mapping plus the differing pairs. */
export function casefold(value: string): string {
  let out = "";
  for (const character of value)
    out += CASEFOLD.get(character) ?? character.toLowerCase();
  return out;
}

/** Python `bytes.split()` with no arguments, for Git metadata fields. */
function splitAsciiWhitespace(value: string): string[] {
  return value.split(ASCII_WHITESPACE).filter((part) => part.length > 0);
}

/** Python `b"...".split(b"\0")` without empty records. */
function splitNul(data: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];
  let start = 0;
  for (let index = 0; index < data.length; index += 1) {
    if (data[index] === 0) {
      if (index > start) out.push(data.subarray(start, index));
      start = index + 1;
    }
  }
  if (start < data.length) out.push(data.subarray(start));
  return out;
}

function parseIpv4(candidate: string): number | null {
  const octets = candidate.split(".");
  if (octets.length !== 4) return null;
  let value = 0;
  for (const octet of octets) {
    if (!/^[0-9]+$/u.test(octet)) return null;
    if (octet.length > 3) return null;
    if (octet !== "0" && octet.startsWith("0")) return null;
    const number = Number(octet);
    if (number > 255) return null;
    value = value * 256 + number;
  }
  return value;
}

function parseHextet(hextet: string): bigint | null {
  if (!/^[0-9a-fA-F]+$/u.test(hextet)) return null;
  if (hextet.length > 4) return null;
  return BigInt(parseInt(hextet, 16));
}

function parseIpv6(candidate: string): bigint | null {
  const percent = candidate.indexOf("%");
  let address = candidate;
  if (percent !== -1) {
    address = candidate.slice(0, percent);
    const scope = candidate.slice(percent + 1);
    if (scope.length === 0 || scope.includes("%")) return null;
  }
  if (address.length === 0 || address.length > 45) return null;

  // Python splits with maxsplit=9, so at most ten fields are produced.
  let parts = address.split(":", 9);
  if (parts.length < 3) return null;

  const last = parts[parts.length - 1] as string;
  if (last.includes(".")) {
    const mapped = parseIpv4(last);
    if (mapped === null) return null;
    parts = parts.slice(0, -1);
    parts.push(
      ((mapped >>> 16) & 0xffff).toString(16),
      (mapped & 0xffff).toString(16),
    );
  }
  if (parts.length > 9) return null;

  let skip = -1;
  for (let index = 1; index < parts.length - 1; index += 1) {
    if (parts[index] === "") {
      if (skip !== -1) return null;
      skip = index;
    }
  }

  let high: number;
  let low: number;
  let skipped: number;
  if (skip !== -1) {
    high = skip;
    low = parts.length - skip - 1;
    if (parts[0] === "") {
      high -= 1;
      if (high !== 0) return null;
    }
    if (parts[parts.length - 1] === "") {
      low -= 1;
      if (low !== 0) return null;
    }
    skipped = 8 - (high + low);
    if (skipped < 1) return null;
  } else {
    if (parts.length !== 8) return null;
    if (parts[0] === "" || parts[parts.length - 1] === "") return null;
    high = parts.length;
    low = 0;
    skipped = 0;
  }

  let value = 0n;
  for (let index = 0; index < high; index += 1) {
    const hextet = parseHextet(parts[index] as string);
    if (hextet === null) return null;
    value = (value << 16n) | hextet;
  }
  value <<= 16n * BigInt(skipped);
  for (let index = parts.length - low; index < parts.length; index += 1) {
    const hextet = parseHextet(parts[index] as string);
    if (hextet === null) return null;
    value = (value << 16n) | hextet;
  }
  return value;
}

/** IPv6 unique-local addresses, compressed or full. */
function isUlaAddress(candidate: string): boolean {
  const halves = candidate.toLowerCase().split("::");
  if (halves.length > 2) return false;
  const groups = (half: string | undefined): string[] =>
    half === undefined || half.length === 0 ? [] : half.split(":");
  const head = groups(halves[0]);
  const tail = groups(halves[1]);
  if (![...head, ...tail].every((group) => /^[0-9a-f]{1,4}$/u.test(group)))
    return false;
  if (!/^f[cd][0-9a-f]{2}$/u.test(head[0] ?? "")) return false;
  const total = head.length + tail.length;
  return halves.length === 2 ? total <= 7 : total <= 8;
}

/** Python `ipaddress.ip_address` with the flags the guard inspects. */
export function parseAddress(candidate: string): AddressInfo | null {
  const ipv4 = parseIpv4(candidate);
  if (ipv4 !== null) {
    return {
      version: 4,
      loopback: ipv4 >>> 24 === 0x7f,
      unspecified: ipv4 === 0,
    };
  }
  const ipv6 = parseIpv6(candidate);
  if (ipv6 === null) return null;
  if (ipv6 >> 32n === 0xffffn) {
    const mapped = Number(ipv6 & 0xffffffffn);
    return {
      version: 6,
      loopback: mapped >>> 24 === 0x7f,
      unspecified: mapped === 0,
    };
  }
  return { version: 6, loopback: ipv6 === 1n, unspecified: ipv6 === 0n };
}

function readTerms(): string[] | null {
  const file = TERMS_VARIABLES.map((name) => process.env[name]).find(
    (value) => value !== undefined && value.length > 0,
  );
  if (!file) return null;
  const decoded = decodeUtf8(readFileSync(file));
  if (decoded === null) throw new Error("terms file is not UTF-8");
  return splitLines(decoded.replace(/\r\n?/gu, "\n")).filter(
    (term) => !ALLOWED_ACCOUNT_NAMES.has(term.trim().toLowerCase()),
  );
}

/** Labels for a text body, shared by file content and commit messages. */
function scanText(text: string): Set<string> {
  const labels = new Set<string>();
  // A documented placeholder MAC is not a device identifier.
  const scrubbed = text.replace(
    /\b(?:aa:bb:cc:dd:ee:ff|00:00:00:00:00:00|ff:ff:ff:ff:ff:ff)\b/giu,
    " ",
  );
  for (const [label, pattern] of RULES) {
    if (pattern.test(scrubbed)) labels.add(label);
  }

  const consider = (candidate: string, end: number): void => {
    // The generic tailnet range (100.64/10, written in full in the reference) is a placeholder, not an address.
    if (
      candidate === ["100", "64", "0", "0"].join(".") &&
      text.startsWith("/10", end) &&
      !UNICODE_DIGIT.test(text.slice(end + 3, end + 4))
    ) {
      return;
    }
    if (isUlaAddress(candidate)) labels.add("private network address");
    // A Windows capability version ends in a dotted number, not an address.
    if (text.slice(0, end - candidate.length).endsWith("~~~~")) return;
    const address = parseAddress(candidate);
    if (address !== null && !address.loopback && !address.unspecified) {
      labels.add("network address");
    }
  };
  for (const pattern of [ADDRESS, IPV6]) {
    pattern.lastIndex = 0;
    for (const match of text.matchAll(pattern)) {
      consider(match[0], (match.index ?? 0) + match[0].length);
    }
  }

  const terms = readTerms();
  if (terms !== null) {
    const folded = casefold(text);
    const listed = terms
      .map((term) => pyStrip(term))
      .some((term) => term.length > 0 && folded.includes(casefold(term)));
    if (listed) labels.add("private denylist term");
  }
  return labels;
}

/** Structural labels that stop text scanning, or `null` for decodable text. */
function structuralLabels(data: Uint8Array): Set<string> | null {
  if (data.length > MAX_BYTES) return new Set(["oversize file"]);
  if (data.includes(0)) return new Set(["binary content"]);
  if (decodeUtf8(data) === null) return new Set(["non-UTF-8 content"]);
  return null;
}

/** Labels for a blob, following the Python `findings()` rules exactly. */
export function findings(data: Uint8Array): Set<string> {
  const structural = structuralLabels(data);
  if (structural !== null) return structural;
  return scanText(decodeText(data));
}

/**
 * Labels for a commit message. A message may name a vendor's no-reply service
 * address in a trailer; file content may not. All other rules still apply.
 */
export function commitMessageFindings(data: Uint8Array): Set<string> {
  const structural = structuralLabels(data);
  if (structural !== null) return structural;
  return scanText(decodeText(data).replace(VENDOR_COMMIT_NOREPLY, " "));
}

/** Identity labels; service addresses are only tolerated when scanning history. */
/**
 * Identity labels. GitHub Actions runs the checks with GitHub's service
 * no-reply address; that address belongs to no person, so it is always
 * accepted. A personal address is never accepted.
 */
export function identityFindings(emails: readonly string[]): Set<string> {
  if (emails.length !== 2) return new Set(["incomplete Git identity"]);
  const rejected = emails.some(
    (email) => !GITHUB_NOREPLY.test(email) && email !== SERVICE_EMAIL,
  );
  return rejected
    ? new Set(["non-GitHub-no-reply author or committer email"])
    : new Set();
}

/** Labels for a path in the index or a tree, including the name-based rule. */
export function filenameFindings(name: Uint8Array): Set<string> {
  const labels = findings(name);
  const base = credentialFilename(name);
  if (
    (base.startsWith(".env") &&
      !/^\.env\.(?:example|sample|template)$/u.test(base)) ||
    CREDENTIAL_BASENAMES.has(base) ||
    CREDENTIAL_SUFFIXES.some((suffix) => base.endsWith(suffix))
  ) {
    labels.add("credential filename");
  }
  return labels;
}

function git(root: string, ...args: string[]): Uint8Array {
  const result = Bun.spawnSync(["git", "-C", root, ...args], {
    stdout: "pipe",
    stderr: "pipe",
    stdin: "ignore",
  });
  if (result.exitCode !== 0) throw new Error("git command failed");
  return new Uint8Array(result.stdout);
}

interface TreeEntry {
  name: Uint8Array;
  mode: string;
  object: string;
}

function* entries(root: string, revision?: string): Generator<TreeEntry> {
  if (revision !== undefined) {
    for (const record of splitNul(
      git(root, "ls-tree", "-rz", "--full-tree", revision),
    )) {
      const tab = record.indexOf(0x09);
      if (tab === -1) throw new Error("malformed ls-tree record");
      const metadata = splitAsciiWhitespace(
        Buffer.from(record.subarray(0, tab)).toString("latin1"),
      );
      if (metadata.length !== 3) throw new Error("malformed ls-tree metadata");
      yield {
        name: record.subarray(tab + 1),
        mode: metadata[0] as string,
        object: metadata[2] as string,
      };
    }
    return;
  }
  for (const record of splitNul(git(root, "ls-files", "--stage", "-z"))) {
    const tab = record.indexOf(0x09);
    if (tab === -1) throw new Error("malformed index record");
    const metadata = splitAsciiWhitespace(
      Buffer.from(record.subarray(0, tab)).toString("latin1"),
    );
    if (metadata.length !== 3) throw new Error("malformed index metadata");
    if (metadata[2] !== "0")
      throw new Error("Unresolved Git index; check cannot complete");
    yield {
      name: record.subarray(tab + 1),
      mode: metadata[0] as string,
      object: metadata[1] as string,
    };
  }
}

function credentialFilename(name: Uint8Array): string {
  const value = looseDecode(name);
  const slash = value.lastIndexOf("/");
  return (slash === -1 ? value : value.slice(slash + 1)).toLowerCase();
}

function tryStat(path: Buffer, follow: boolean): Stats | undefined {
  try {
    return follow ? statSync(path) : lstatSync(path);
  } catch {
    return undefined;
  }
}

function repositoryPath(root: string, name: Uint8Array): Buffer {
  return Buffer.concat([
    Buffer.from(root, "utf8"),
    Buffer.from("/", "utf8"),
    Buffer.from(name),
  ]);
}

function reportRepositoryItem(labels: Set<string>): void {
  console.error(
    "Review required in repository item: " + [...labels].sort().join(", "),
  );
}

function reportGitMetadata(labels: Set<string>): void {
  console.error(
    "Review required in Git metadata: " + [...labels].sort().join(", "),
  );
}

export function scan(options: Options): number {
  const root = pyStrip(
    decodeText(git(options.root, "rev-parse", "--show-toplevel")),
  );
  let failures = 0;
  const checked = new Set<string>();

  const check = (
    name: Uint8Array,
    mode: string,
    data: Uint8Array,
    commitMessage = false,
  ): void => {
    // `.claude/skills/<name>` is a required relative link to its source.
    if (allowedSkillLink(root, name)) return;
    const labels = filenameFindings(name);
    if (mode !== "100644" && mode !== "100755") {
      labels.add("symlink or submodule");
    } else {
      for (const label of commitMessage
        ? commitMessageFindings(data)
        : findings(data))
        labels.add(label);
    }
    if (labels.size > 0) {
      failures += 1;
      reportRepositoryItem(labels);
    }
  };

  if (options.identity) {
    const emails: string[] = [];
    for (const variable of ["GIT_AUTHOR_IDENT", "GIT_COMMITTER_IDENT"]) {
      const identity = tryGit(root, "var", variable);
      const match = identity === null ? null : IDENTITY.exec(pyStrip(identity));
      if (match === null) {
        emails.length = 0;
        break;
      }
      emails.push(match[1] as string);
    }
    // A CI runner has no configured Git identity, so verify the tip commit's
    // recorded identities instead; a merge commit carries the service address.
    if (emails.length !== 2) {
      emails.push(
        ...splitLines(
          decodeText(git(root, "show", "-s", "--format=%ae%n%ce", "HEAD")),
        ),
      );
    }
    const labels = identityFindings(emails);
    if (labels.size > 0) {
      failures += 1;
      reportGitMetadata(labels);
    }
  } else if (options.history || options.range !== null) {
    // Local history deliberately excludes refs/stash and T3 checkpoints: they
    // are machine-local snapshots, not published history. CI checks out a ref
    // whose fetched branches, tags and remotes are the whole publication set.
    const revisions = options.range ?? ["--branches", "--tags", "--remotes"];
    const commits = splitLines(decodeText(git(root, "rev-list", ...revisions)));
    for (const revision of commits) {
      const emails = splitLines(
        decodeText(git(root, "show", "-s", "--format=%ae%n%ce", revision)),
      );
      const labels = identityFindings(emails);
      if (labels.size > 0) {
        failures += 1;
        reportGitMetadata(labels);
      }
      check(
        COMMIT_MESSAGE_NAME,
        "100644",
        git(root, "show", "-s", "--format=%B", revision),
        true,
      );
      for (const entry of entries(root, revision)) {
        const key = `${Buffer.from(entry.name).toString("hex")}:${entry.mode}:${entry.object}`;
        if (checked.has(key)) continue;
        checked.add(key);
        const data =
          entry.mode === "100644" || entry.mode === "100755"
            ? git(root, "cat-file", "blob", entry.object)
            : EMPTY;
        check(entry.name, entry.mode, data);
      }
    }
  } else if (options.staged) {
    // Only the blobs the commit would add or change. Scanning the whole index
    // would block every commit in a repository that still carries an older
    // finding in an untouched file.
    const staged = new Set(
      splitNul(
        git(
          root,
          "diff",
          "--cached",
          "--name-only",
          "--diff-filter=ACMR",
          "-z",
        ),
      ).map((name) => Buffer.from(name).toString("hex")),
    );
    for (const entry of entries(root)) {
      if (!staged.has(Buffer.from(entry.name).toString("hex"))) continue;
      const data =
        entry.mode === "100644" || entry.mode === "100755"
          ? git(root, "cat-file", "blob", entry.object)
          : EMPTY;
      check(entry.name, entry.mode, data);
    }
  } else {
    const names = splitNul(
      git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z"),
    );
    const seen = new Set<string>();
    for (const name of names) {
      const key = Buffer.from(name).toString("hex");
      if (seen.has(key)) continue;
      seen.add(key);
      const path = repositoryPath(root, name);
      if (tryStat(path, false)?.isSymbolicLink() === true) {
        check(name, "120000", EMPTY);
        continue;
      }
      const stat = tryStat(path, true);
      if (stat?.isFile() === true) {
        if (stat.size > MAX_BYTES) {
          check(name, "100644", new Uint8Array(MAX_BYTES + 1).fill(0x20));
        } else {
          check(name, "100644", readFileSync(path));
        }
      } else if (stat !== undefined) {
        check(name, "160000", EMPTY);
      }
    }
  }

  if (failures > 0) {
    console.error(
      `Blocked: ${failures} item(s). No filenames or matched values printed.`,
    );
    return 1;
  }
  console.log(
    "Configured privacy checks passed; manual review is still required.",
  );
  return 0;
}

// ---------------------------------------------------------------------------
// Repository helpers
// ---------------------------------------------------------------------------

const ZERO = /^0+$/;

/** `.claude/skills/<name>` is a required relative link to its `.agents` source. */
function allowedSkillLink(root: string, name: Uint8Array): boolean {
  const value = Buffer.from(name).toString("utf8");
  const match = /^\.claude\/skills\/([A-Za-z0-9._-]+)$/u.exec(value);
  if (match === null) return false;
  const path = join(root, value);
  try {
    return (
      lstatSync(path).isSymbolicLink() &&
      readlinkSync(path) === `../../.agents/skills/${match[1] as string}`
    );
  } catch {
    return false;
  }
}

interface PushRef {
  localRef: string;
  localOid: string;
  remoteRef: string;
  remoteOid: string;
}

/** Run Git and return null instead of throwing, for optional lookups. */
function tryGit(root: string, ...args: string[]): string | null {
  const result = Bun.spawnSync(["git", "-C", root, ...args], {
    stdout: "pipe",
    stderr: "pipe",
    stdin: "ignore",
  });
  if (result.exitCode !== 0) return null;
  return decodeUtf8(new Uint8Array(result.stdout));
}

function repositoryRoot(): string {
  const result = Bun.spawnSync(["git", "rev-parse", "--show-toplevel"], {
    stdout: "pipe",
    stderr: "pipe",
    stdin: "ignore",
  });
  if (result.exitCode !== 0) throw new Error("not inside a Git worktree");
  return decodeText(new Uint8Array(result.stdout)).trim();
}

function runInherit(command: string, args: string[], cwd: string): number {
  const result = spawnSync(command, args, { cwd, stdio: "inherit" });
  if (result.error) {
    console.error(
      `Could not run ${command}; install pinned tools with \`mise install\`.`,
    );
    return 2;
  }
  return result.status ?? 1;
}

function just(root: string, recipes: string[]): number {
  return runInherit(
    "just",
    ["--justfile", join(root, "justfile"), ...recipes],
    root,
  );
}

function readStdin(): string {
  if (process.stdin.isTTY) return "";
  try {
    return readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

/** Parse pre-push stdin; malformed and blank lines are ignored. */
export function pushRefs(input: string): PushRef[] {
  const refs: PushRef[] = [];
  for (const line of input.split("\n")) {
    const fields = line.trim().split(/\s+/u);
    if (fields.length < 4) continue;
    const [localRef, localOid, remoteRef, remoteOid] = fields as [
      string,
      string,
      string,
      string,
    ];
    refs.push({ localRef, localOid, remoteRef, remoteOid });
  }
  return refs;
}

/**
 * Return the first ref that would update main, unless ALLOW_MAIN_PUSH=1 is set
 * for an owner-approved recovery. Deletions are not updates to main.
 */
export function blockedRef(
  refs: PushRef[],
  allowMainPush: string | undefined,
): PushRef | null {
  if (allowMainPush === "1") return null;
  for (const ref of refs) {
    if (ZERO.test(ref.localOid)) continue;
    if (ref.remoteRef === "refs/heads/main") return ref;
  }
  return null;
}

function mergeBase(root: string, oid: string): string | null {
  const result = Bun.spawnSync(
    ["git", "-C", root, "merge-base", oid, "refs/remotes/origin/main"],
    { stdout: "pipe", stderr: "ignore", stdin: "ignore" },
  );
  if (result.exitCode !== 0) return null;
  const value = decodeText(new Uint8Array(result.stdout)).trim();
  return value.length > 0 ? value : null;
}

function defaultGitleaksRange(): string {
  const base = process.env.BASE_SHA;
  const head = process.env.HEAD_SHA;
  if (
    base !== undefined &&
    head !== undefined &&
    base.length > 0 &&
    !ZERO.test(base)
  ) {
    return `${base}..${head}`;
  }
  const baseRef = process.env.GITHUB_BASE_REF;
  if (baseRef !== undefined && baseRef.length > 0)
    return `origin/${baseRef}..HEAD`;
  const before = process.env.GITHUB_EVENT_BEFORE;
  const sha = process.env.GITHUB_SHA;
  if (
    before !== undefined &&
    sha !== undefined &&
    before.length > 0 &&
    !ZERO.test(before)
  ) {
    return `${before}..${sha}`;
  }
  // Locally, scan the change, not immutable published history; `history` is the
  // full-history recipe. A repository with one commit scans that commit.
  const parent = Bun.spawnSync(
    ["git", "rev-parse", "--verify", "--quiet", "HEAD~1"],
    { stdout: "ignore", stderr: "ignore", stdin: "ignore" },
  );
  return parent.exitCode === 0 ? "HEAD~1..HEAD" : "HEAD";
}

function gitleaks(root: string, args: readonly string[]): number {
  const version = Bun.spawnSync(["gitleaks", "version"], {
    stdout: "ignore",
    stderr: "ignore",
    stdin: "ignore",
  });
  if (version.exitCode !== 0) {
    console.error("gitleaks is not installed; run `mise install`.");
    return 2;
  }
  const requested = args[0];
  const range =
    requested !== undefined && requested.length > 0
      ? requested
      : defaultGitleaksRange();
  console.log(`gitleaks: scanning ${range}`);
  return runInherit(
    "gitleaks",
    ["git", "--redact", "--no-banner", `--log-opts=${range}`, "."],
    root,
  );
}

function whitespace(root: string, staged: boolean): number {
  const args = ["diff", ...(staged ? ["--cached"] : []), "--check"];
  return runInherit("git", args, root);
}

function recipeNames(root: string): Set<string> {
  const names = new Set<string>();
  let text = "";
  try {
    text = readFileSync(join(root, "justfile"), "utf8");
  } catch {
    return names;
  }
  for (const line of text.split("\n")) {
    const match = /^([A-Za-z0-9_-]+)(?:\s+[^:]*)?:(?!=)/u.exec(line);
    if (match !== null && match[1] !== undefined) names.add(match[1]);
  }
  return names;
}

function skillNames(directory: string): string[] {
  if (!existsSync(directory)) return [];
  return readdirSync(directory, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
}

function linkNames(directory: string): string[] {
  if (!existsSync(directory)) return [];
  return readdirSync(directory).sort();
}

function isLink(path: string): boolean {
  try {
    return lstatSync(path).isSymbolicLink();
  } catch {
    return false;
  }
}

function agentFiles(root: string): number {
  const agentDirectory = join(root, ".agents", "skills");
  const claudeDirectory = join(root, ".claude", "skills");
  const skills = skillNames(agentDirectory);
  const links = linkNames(claudeDirectory);
  const recipes = recipeNames(root);
  let failures = 0;

  for (const name of skills) {
    if (!links.includes(name)) {
      console.error(`agent-files: missing .claude/skills/${name} link`);
      failures += 1;
    }
  }
  for (const name of links) {
    if (!skills.includes(name)) {
      console.error(
        `agent-files: .claude/skills/${name} has no .agents/skills source`,
      );
      failures += 1;
    }
  }

  for (const name of skills) {
    const file = join(agentDirectory, name, "SKILL.md");
    if (!existsSync(file)) {
      console.error(`agent-files: ${name} has no SKILL.md`);
      failures += 1;
      continue;
    }
    const text = readFileSync(file, "utf8");
    const frontmatter = /^---\r?\n([\s\S]*?)\r?\n---/u.exec(text);
    if (frontmatter === null) {
      console.error(`agent-files: ${name} has no frontmatter`);
      failures += 1;
    } else {
      const block = frontmatter[1] ?? "";
      if (!/^name:\s*\S/mu.test(block)) {
        console.error(`agent-files: ${name} frontmatter has no name`);
        failures += 1;
      }
      if (!/^description:\s*\S/mu.test(block)) {
        console.error(`agent-files: ${name} frontmatter has no description`);
        failures += 1;
      }
    }

    const link = join(claudeDirectory, name);
    if (isLink(link)) {
      const target = readlinkSync(link);
      if (target !== `../../.agents/skills/${name}`) {
        console.error(
          `agent-files: .claude/skills/${name} points at ${target}`,
        );
        failures += 1;
      }
    } else if (links.includes(name)) {
      console.error(
        `agent-files: .claude/skills/${name} is not a symbolic link`,
      );
      failures += 1;
    }

    for (const match of text.matchAll(/\bjust\s+([a-z][a-z0-9-]*)/gu)) {
      const recipe = match[1];
      if (recipe !== undefined && !recipes.has(recipe)) {
        console.error(`agent-files: ${name} names missing recipe ${recipe}`);
        failures += 1;
      }
    }
  }

  if (failures > 0) {
    console.error(`agent-files: ${failures} problem(s)`);
    return 1;
  }
  console.log(`agent-files: ${skills.length} skill(s) and links agree`);
  return 0;
}

function inspectRepository(root: string): number {
  const branch = decodeText(
    git(root, "rev-parse", "--abbrev-ref", "HEAD"),
  ).trim();
  const status = decodeText(git(root, "status", "--short")).trim();
  const skills = skillNames(join(root, ".agents", "skills"));
  console.log(`repository: ${basename(root)}`);
  console.log(`branch: ${branch}`);
  console.log(`dirty: ${status.length === 0 ? "no" : "yes"}`);
  console.log(`skills: ${skills.length === 0 ? "none" : skills.join(", ")}`);
  for (const tool of ["bun", "just", "gitleaks"]) {
    const result = Bun.spawnSync([tool, "--version"], {
      stdout: "pipe",
      stderr: "ignore",
      stdin: "ignore",
    });
    const value =
      result.exitCode === 0
        ? decodeText(new Uint8Array(result.stdout)).trim().split("\n")[0]
        : "missing";
    console.log(`${tool}: ${value}`);
  }
  return 0;
}

function preCommit(root: string): number {
  return just(root, [
    "privacy-identity",
    "privacy-staged",
    "whitespace-staged",
  ]);
}

/**
 * Commits a push would publish without a good signature (C2.7). Tags are
 * skipped like the `.githooks` launcher did, and only commits new to the remote
 * are checked, so GitHub-signed history does not block a new branch.
 */
function unsignedCommits(root: string, ref: PushRef): string[] {
  if (ref.localRef.startsWith("refs/tags/")) return [];
  const range = ZERO.test(ref.remoteOid)
    ? [ref.localOid, "--not", "--remotes=origin"]
    : [`${ref.remoteOid}..${ref.localOid}`];
  const output = decodeText(git(root, "log", "--format=%H %G?", ...range));
  const unsigned: string[] = [];
  for (const line of splitLines(output)) {
    const match = /^([0-9a-f]{40}) (\S)$/u.exec(line);
    if (match !== null && match[2] !== "G") unsigned.push(match[1] as string);
  }
  return unsigned;
}

function prePush(
  root: string,
  input: string,
  allowMainPush: string | undefined,
): number {
  const refs = pushRefs(input);
  const blocked = blockedRef(refs, allowMainPush);
  if (blocked !== null) {
    console.error(
      `BLOCKED: refusing to push ${blocked.localRef} to ${blocked.remoteRef}.`,
    );
    console.error("main changes only through a branch and a pull request.");
    console.error("Set ALLOW_MAIN_PUSH=1 only for an owner-approved recovery.");
    return 1;
  }

  let identityChecked = false;
  for (const ref of refs) {
    if (ZERO.test(ref.localOid)) continue;
    if (!identityChecked) {
      const status = just(root, ["privacy-identity"]);
      if (status !== 0) return status;
      identityChecked = true;
    }
    const unsigned = unsignedCommits(root, ref);
    if (unsigned.length > 0) {
      for (const oid of unsigned) {
        console.error(
          `pre-push: commit ${oid} is not signed with a known key.`,
        );
      }
      console.error(
        "Commits must be SSH-signed (C2.7); amend or rebase to sign them.",
      );
      return 1;
    }
    const base = ZERO.test(ref.remoteOid)
      ? mergeBase(root, ref.localOid)
      : ref.remoteOid;
    if (base === null) {
      console.error(
        `pre-push: no merge base for ${ref.localOid}; scanning all reachable commits`,
      );
      const secrets = gitleaks(root, [ref.localOid]);
      if (secrets !== 0) return secrets;
      continue;
    }
    const secrets = gitleaks(root, [`${base}..${ref.localOid}`]);
    if (secrets !== 0) return secrets;
  }
  return 0;
}

function history(root: string): number {
  const status = scan({
    staged: false,
    history: true,
    range: null,
    identity: false,
    root,
  });
  if (status !== 0) return status;
  return gitleaks(root, ["--all"]);
}

// ---------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------

const LONG_OPTIONS = [
  "--staged",
  "--history",
  "--range",
  "--identity",
  "--root",
  "--help",
] as const;

function programName(): string {
  return basename(process.argv[1] ?? "git-hook.ts");
}

function resolveLong(name: string): string | null {
  const exact = LONG_OPTIONS.find((option) => option === name);
  if (exact !== undefined) return exact;
  const matches = LONG_OPTIONS.filter((option) => option.startsWith(name));
  if (matches.length > 1) {
    throw new UsageError(
      `ambiguous option: ${name} could match ${matches.join(", ")}`,
    );
  }
  return matches.length === 1 ? (matches[0] as string) : null;
}

export function parseArgs(argv: readonly string[]): Options {
  let staged = false;
  let history = false;
  let identity = false;
  let range: string[] | null = null;
  let root = repositoryRoot();
  let selected: string | null = null;
  const positional: string[] = [];
  let index = 0;

  const select = (flag: string): void => {
    if (selected !== null && selected !== flag) {
      throw new UsageError(
        `argument ${flag}: not allowed with argument ${selected}`,
      );
    }
    selected = flag;
  };

  while (index < argv.length) {
    const argument = argv[index] as string;
    if (argument === "--") {
      positional.push(...argv.slice(index + 1));
      break;
    }
    if (argument === "-h") throw new HelpRequested();
    if (!argument.startsWith("-") || argument === "-") {
      positional.push(argument);
      index += 1;
      continue;
    }
    if (!argument.startsWith("--"))
      throw new UsageError(`unrecognized arguments: ${argument}`);

    const equals = argument.indexOf("=");
    const name = equals === -1 ? argument : argument.slice(0, equals);
    const inline = equals === -1 ? undefined : argument.slice(equals + 1);
    const resolved = resolveLong(name);
    if (resolved === null)
      throw new UsageError(`unrecognized arguments: ${argument}`);
    if (resolved === "--help") throw new HelpRequested();
    if (resolved === "--root") {
      let value = inline;
      if (value === undefined) {
        index += 1;
        if (index >= argv.length)
          throw new UsageError("argument --root: expected one argument");
        value = argv[index] as string;
      }
      root = value;
      index += 1;
      continue;
    }
    if (inline !== undefined) {
      throw new UsageError(
        `argument ${resolved}: ignored explicit argument '${inline}'`,
      );
    }
    if (resolved === "--staged") {
      select("--staged");
      staged = true;
      index += 1;
      continue;
    }
    if (resolved === "--history") {
      select("--history");
      history = true;
      index += 1;
      continue;
    }
    if (resolved === "--identity") {
      select("--identity");
      identity = true;
      index += 1;
      continue;
    }
    select("--range");
    const values: string[] = [];
    index += 1;
    while (index < argv.length) {
      const value = argv[index] as string;
      if (value === "--") break;
      if (value.startsWith("-") && value.length > 1) break;
      values.push(value);
      index += 1;
    }
    if (values.length === 0)
      throw new UsageError("argument --range: expected at least one argument");
    range = values;
  }

  if (positional.length > 0)
    throw new UsageError(`unrecognized arguments: ${positional.join(" ")}`);
  return { staged, history, range, identity, root };
}

function usageLine(): string {
  return "usage: git-hook.ts <pre-commit|pre-push|privacy|privacy-identity|privacy-staged|privacy-range|privacy-commits|whitespace|whitespace-staged|gitleaks|agent-files|history|inspect> [args]";
}

function helpText(): string {
  return [
    usageLine(),
    "",
    "Canonical Git hook and privacy check. Matched values are never printed.",
    "",
    "  pre-commit                     identity, staged blobs and staged whitespace",
    "  pre-push                       refuse main, then scan the pushed range",
    "  privacy [--root DIR]           non-ignored worktree files",
    "  privacy-staged [--root DIR]    exact staged blobs",
    "  privacy-range REV BASE         commits in BASE..REV",
    "  privacy-commits REV            every commit reachable from REV",
    "  whitespace                     git diff --check",
    "  whitespace-staged              git diff --cached --check",
    "  gitleaks [RANGE]               gitleaks over RANGE or the CI/PR range",
    "  agent-files                    .agents/skills and .claude/skills agree",
    "  history                        every published ref",
    "  inspect                        read-only local orientation",
    "",
  ].join("\n");
}

function commandLine(argv: readonly string[]): number {
  const command = argv[0];
  const root = repositoryRoot();
  switch (command) {
    case "pre-commit":
      return preCommit(root);
    case "pre-push":
      return prePush(root, readStdin(), process.env.ALLOW_MAIN_PUSH);
    case "privacy-identity":
      return scan({
        staged: false,
        history: false,
        range: null,
        identity: true,
        root,
      });
    case "privacy":
      return scan({
        staged: false,
        history: false,
        range: null,
        identity: false,
        root,
      });
    case "privacy-staged":
      return scan({
        staged: true,
        history: false,
        range: null,
        identity: false,
        root,
      });
    case "privacy-range": {
      const revision = argv[1];
      const base = argv[2];
      if (revision === undefined || base === undefined) {
        console.error("usage: git-hook.ts privacy-range REV BASE");
        return 2;
      }
      return scan({
        staged: false,
        history: false,
        range: [revision, `^${base}`],
        identity: false,
        root,
      });
    }
    case "privacy-commits": {
      const revision = argv[1];
      if (revision === undefined) {
        console.error("usage: git-hook.ts privacy-commits REV");
        return 2;
      }
      return scan({
        staged: false,
        history: false,
        range: [revision],
        identity: false,
        root,
      });
    }
    case "whitespace":
      return whitespace(root, false);
    case "whitespace-staged":
      return whitespace(root, true);
    case "gitleaks":
      return gitleaks(root, argv.slice(1));
    case "agent-files":
      return agentFiles(root);
    case "history":
      return history(root);
    case "inspect":
      return inspectRepository(root);
    case "--help":
    case "-h":
    case "help":
      process.stdout.write(helpText());
      return 0;
    default:
      break;
  }
  // Legacy flag form, kept so an older recipe or a by-hand invocation works.
  try {
    return scan(parseArgs(argv));
  } catch (error) {
    if (error instanceof HelpRequested) {
      process.stdout.write(helpText());
      return 0;
    }
    if (error instanceof UsageError) {
      process.stderr.write(`${usageLine()}\n`);
      process.stderr.write(`${programName()}: error: ${error.message}\n`);
      return 2;
    }
    throw error;
  }
}

export function main(argv: readonly string[]): number {
  try {
    return commandLine(argv);
  } catch {
    console.error(
      "Git hook or privacy check could not complete; publication must stop.",
    );
    return 2;
  }
}

if (import.meta.main) {
  process.exit(main(process.argv.slice(2)));
}
