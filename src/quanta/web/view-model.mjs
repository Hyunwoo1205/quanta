/** Pure presentation helpers. Authored JSON is never rebuilt from parsed numbers. */

export const terminalStatuses = new Set(["SUCCEEDED", "FAILED", "CANCELLED"]);

/** Only the fixed same-origin Access navigation routes are accepted. */
export function authConfiguration(value) {
  if (value?.mode === "bearer") return { mode: "bearer", authenticated: false };
  if (value?.mode !== "access" || typeof value.authenticated !== "boolean"
      || value.login_url !== "/" || value.logout_url !== "/cdn-cgi/access/logout") {
    throw new TypeError("연결 방식을 확인할 수 없습니다.");
  }
  if (value.authenticated && (typeof value.principal?.email !== "string" || !value.principal.email
      || typeof value.principal?.owner !== "string" || !value.principal.owner)) {
    throw new TypeError("로그인 정보를 확인할 수 없습니다.");
  }
  return { mode: "access", authenticated: value.authenticated,
    principal: value.authenticated ? { email: value.principal.email, owner: value.principal.owner } : null,
    login_url: "/", logout_url: "/cdn-cgi/access/logout" };
}

/** Session cookies are sent only to this origin; bearer tokens stay in memory. */
export function authRequestOptions(mode, token, { json = true } = {}) {
  if (mode !== "bearer" && mode !== "access") throw new TypeError("연결 방식을 먼저 확인하세요.");
  const headers = json ? { "Content-Type": "application/json" } : {};
  if (mode === "bearer") headers.Authorization = "Bearer " + token;
  return { headers, credentials: mode === "access" ? "same-origin" : "omit",
    redirect: "error", cache: "no-store", referrerPolicy: "no-referrer" };
}

export function isJSONResponse(contentType) {
  return typeof contentType === "string"
    && /^application\/(?:[a-z0-9!#$&^_.+-]+\+)?json(?:\s*;|\s*$)/i.test(contentType.trim());
}

/** A failed fetch alone cannot distinguish a redirect rejection from offline. */
export function accessResponseNeedsLogin(mode, response) {
  if (mode !== "access") return false;
  return response?.status === 401 || response?.status === 403 || response?.redirected === true
    || response?.type === "opaqueredirect"
    || /^text\/html(?:\s*;|\s*$)/i.test(response?.contentType?.trim() ?? "");
}

const statusLabels = Object.freeze({
  QUEUED: "대기 중",
  RUNNING: "실행 중",
  CANCEL_REQUESTED: "취소 요청됨",
  SUCCEEDED: "실행 완료",
  FAILED: "실행 실패",
  CANCELLED: "취소됨",
  SKIPPED: "건너뜀",
  pass: "기준 충족",
  not_converged: "미수렴",
  not_checked: "미확인",
  not_applicable: "해당 없음",
  validated: "검증됨",
  unvalidated: "물리 검증 전",
  valid: "유효함",
  invalid: "오류 있음",
});

export function statusLabel(value) {
  if (value === null || value === undefined || value === "") return "—";
  return Object.hasOwn(statusLabels, value) ? statusLabels[value] : String(value);
}

/** Format a display value only; do not use this output to construct input JSON. */
export function formatNumber(value, digits = 6) {
  if (typeof value !== "number" || !Number.isFinite(value)) return "—";
  if (Object.is(value, -0)) return "-0";
  if (value === 0) return "0";
  const precision = Number.isFinite(digits) ? Math.min(15, Math.max(1, Math.trunc(digits))) : 6;
  const magnitude = Math.abs(value);
  if (magnitude < 1e-3 || magnitude >= 1e5) {
    const [coefficient, exponent] = value.toExponential(precision - 1).split("e");
    return `${trimFraction(coefficient)}e${Number(exponent)}`;
  }
  const fractionalDigits = Math.max(0, precision - Math.floor(Math.log10(magnitude)) - 1);
  return trimFraction(value.toFixed(fractionalDigits));
}

function trimFraction(value) {
  return value.includes(".") ? value.replace(/0+$/, "").replace(/\.$/, "") : value;
}

function jsonText(text) {
  if (typeof text !== "string") throw new TypeError("JSON 텍스트를 입력하세요.");
  return text;
}

/**
 * Parse for the draft summary and basic JSON/root checks only. In particular,
 * JSON.parse cannot retain every authored number lexeme, so this result must
 * never replace the raw definition used by either request-body builder.
 */
export function parseDefinition(text) {
  const value = JSON.parse(jsonText(text));
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("실험 정의는 JSON 객체여야 합니다.");
  }
  return value;
}

/** Token positions refer to the unchanged, already syntax-validated source. */
function tokensOf(text) {
  const tokens = [];
  let offset = 0;
  while (offset < text.length) {
    if (/[\x20\t\r\n]/.test(text[offset])) {
      offset += 1;
      continue;
    }
    const start = offset;
    const first = text[offset];
    if (first === '"') {
      offset += 1;
      while (offset < text.length) {
        if (text[offset] === "\\") offset += 2;
        else if (text[offset++] === '"') break;
      }
    } else if ("{}[]:,".includes(first)) {
      offset += 1;
    } else {
      while (offset < text.length && !/[\x20\t\r\n{}\[\]:,]/.test(text[offset])) offset += 1;
    }
    tokens.push({ raw: text.slice(start, offset), start, end: offset });
  }
  return tokens;
}

/**
 * Return an exact top-level value, preserving signed zero, exponents, large
 * integer lexemes, string escapes and whitespace inside the selected value.
 * Missing members return undefined. A duplicate matching member is ambiguous.
 */
export function rawMember(text, key) {
  const source = jsonText(text);
  const parsed = JSON.parse(source);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new TypeError("JSON 최상위 값은 객체여야 합니다.");
  }
  if (typeof key !== "string") throw new TypeError("JSON 멤버 이름은 문자열이어야 합니다.");
  const tokens = tokensOf(source);
  let index = 1;
  let found;
  let matches = 0;
  while (tokens[index].raw !== "}") {
    const memberName = JSON.parse(tokens[index].raw);
    index += 2; // member name and colon
    const start = tokens[index].start;
    let end;
    if (tokens[index].raw === "{" || tokens[index].raw === "[") {
      let depth = 0;
      do {
        const token = tokens[index++];
        if (token.raw === "{" || token.raw === "[") depth += 1;
        if (token.raw === "}" || token.raw === "]") depth -= 1;
        end = token.end;
      } while (depth > 0);
    } else {
      end = tokens[index++].end;
    }
    if (memberName === key) {
      matches += 1;
      if (matches > 1) throw new SyntaxError(`JSON 멤버가 중복되었습니다: ${key}`);
      found = source.slice(start, end);
    }
    if (tokens[index].raw === ",") index += 1;
  }
  return found;
}

/** Pretty-print tokens, not values: authored number and string lexemes survive. */
export function formatJSONPreservingNumbers(text) {
  const source = jsonText(text);
  JSON.parse(source); // Native syntax validation; never serialize its return value.
  const tokens = tokensOf(source);
  let depth = 0;
  let formatted = "";
  const newline = () => `\n${"  ".repeat(depth)}`;
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index].raw;
    if (token === "{" || token === "[") {
      formatted += token;
      depth += 1;
      const next = tokens[index + 1]?.raw;
      if (next !== "}" && next !== "]") formatted += newline();
    } else if (token === "}" || token === "]") {
      depth -= 1;
      const previous = tokens[index - 1]?.raw;
      if (previous !== "{" && previous !== "[") formatted += newline();
      formatted += token;
    } else if (token === ",") {
      formatted += `,${newline()}`;
    } else if (token === ":") {
      formatted += ": ";
    } else {
      formatted += token;
    }
  }
  return formatted;
}

/** Raw insertion is intentional: JSON.stringify(JSON.parse(text)) erases -0. */
export function buildRevisionBody(title, rawDefinition) {
  if (typeof title !== "string") throw new TypeError("실험 제목은 문자열이어야 합니다.");
  parseDefinition(rawDefinition);
  return `{"schema_version":"0.2.0","title":${JSON.stringify(title)},"definition":${rawDefinition}}`;
}

export function buildValidationBody(rawDefinition) {
  parseDefinition(rawDefinition);
  return `{"schema_version":"0.2.0","definition":${rawDefinition}}`;
}

/** A draft summary is descriptive only; server validation decides support. */
export function summarizeDefinition(definition) {
  const system = definition?.system;
  const steps = Array.isArray(definition?.protocol?.steps) ? definition.protocol.steps : [];
  const axes = Array.isArray(definition?.protocol?.sweep?.axes) ? definition.protocol.sweep.axes : [];
  const branches = axes.reduce((count, axis) => count * (Array.isArray(axis?.values) ? axis.values.length : 0), 1);
  const moduleId = typeof system?.module_id === "string" ? system.module_id : "—";
  const moduleVersion = typeof system?.module_version === "string" ? system.module_version : "";
  return {
    module: moduleVersion ? `${moduleId}@${moduleVersion}` : moduleId,
    operations: [...new Set(steps.map((step) => step?.operation).filter((operation) => typeof operation === "string"))],
    particles: Array.isArray(system?.particles) ? system.particles.length : null,
    branches,
    expandedSteps: branches * steps.length,
  };
}

/** Select the actual registered quantum-result arrays without reconstructing data. */
export function quantumSeries(payload, stateIndex = 0, kind = "wave") {
  const metadata = kind === "wave"
    ? { kind, unit: "m⁻¹ᐟ²", label: "파동함수 Re ψ" }
    : kind === "density"
      ? { kind, unit: "m⁻¹", label: "확률 밀도 |ψ|²" }
      : { kind, unit: "—", label: "지원하지 않는 자료" };
  const unavailable = () => ({ available: false, xs: [], ys: [], ...metadata });
  if ((kind !== "wave" && kind !== "density") || !Number.isInteger(stateIndex) || stateIndex < 0) return unavailable();
  const xs = payload?.x_m;
  // `states` is an object containing real/imag arrays, never an array of states.
  // This series is explicitly Re ψ; imaginary values are not folded into it.
  const ys = kind === "wave" ? payload?.states?.real?.[stateIndex] : payload?.density_per_m?.[stateIndex];
  if (!Array.isArray(xs) || !Array.isArray(ys) || xs.length === 0 || xs.length !== ys.length) return unavailable();
  if (!xs.some((x, index) => typeof x === "number" && typeof ys[index] === "number" && Number.isFinite(x) && Number.isFinite(ys[index]))) return unavailable();
  return { available: true, xs, ys, ...metadata };
}

function expandedDomain(minimum, maximum) {
  if (minimum !== maximum) return [minimum, maximum];
  const amount = Math.max(Math.abs(minimum) * 0.05, Number.MIN_VALUE);
  if (minimum === 0) return [-1, 1];
  const low = minimum - amount;
  const high = maximum + amount;
  return [Number.isFinite(low) ? low : minimum, Number.isFinite(high) ? high : maximum];
}

// Scaling before subtraction avoids overflow for opposite large finite values.
function domainFraction(value, minimum, maximum) {
  const scale = Math.max(Math.abs(minimum), Math.abs(maximum), Number.MIN_VALUE);
  return (value / scale - minimum / scale) / (maximum / scale - minimum / scale);
}

/** Map only real result samples to SVG geometry. No missing data is invented. */
export function chartPoints(xs, ys, width = 640, height = 280, padding = 40) {
  if (![width, height, padding].every(Number.isFinite) || width <= 0 || height <= 0 || padding < 0 || padding * 2 >= Math.min(width, height)) {
    throw new RangeError("그래프 크기와 여백을 확인하세요.");
  }
  const left = padding;
  const right = width - padding;
  const top = padding;
  const bottom = height - padding;
  const geometry = { width, height, padding, left, right, top, bottom };
  const samples = [];
  const count = Math.min(xs?.length ?? 0, ys?.length ?? 0);
  for (let index = 0; index < count; index += 1) {
    if (typeof xs[index] === "number" && typeof ys[index] === "number" && Number.isFinite(xs[index]) && Number.isFinite(ys[index])) {
      samples.push({ x: xs[index], y: ys[index] });
    }
  }
  if (!samples.length) {
    return { ...geometry, points: "", samples: [], xMin: null, xMax: null, yMin: null, yMax: null, zeroY: null, empty: true };
  }
  let xMin = Infinity;
  let xMax = -Infinity;
  let yMin = Infinity;
  let yMax = -Infinity;
  for (const sample of samples) {
    xMin = Math.min(xMin, sample.x);
    xMax = Math.max(xMax, sample.x);
    yMin = Math.min(yMin, sample.y);
    yMax = Math.max(yMax, sample.y);
  }
  [xMin, xMax] = expandedDomain(xMin, xMax);
  [yMin, yMax] = expandedDomain(yMin, yMax);
  for (const sample of samples) {
    sample.px = left + domainFraction(sample.x, xMin, xMax) * (right - left);
    sample.py = bottom - domainFraction(sample.y, yMin, yMax) * (bottom - top);
  }
  const zeroY = yMin <= 0 && yMax >= 0 ? bottom - domainFraction(0, yMin, yMax) * (bottom - top) : null;
  return {
    ...geometry,
    points: samples.map((sample) => `${sample.px},${sample.py}`).join(" "),
    samples,
    xMin,
    xMax,
    yMin,
    yMax,
    zeroY,
    empty: false,
  };
}
