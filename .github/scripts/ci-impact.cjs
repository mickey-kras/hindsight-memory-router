const { execFileSync } = require('node:child_process');

const WORKERS = ['python', 'ui', 'release'];
const PYTHON_CACHE_NAMES = new Set(['.mypy_cache', '.pytest_cache', '.ruff_cache', '__pycache__']);
const full = () => Object.fromEntries(WORKERS.map(name => [name, true]));

function parseDiff(data) {
  // -z is mandatory: whitespace, newlines and Git's quoted path syntax must
  // never turn a partial/ambiguous filename into an allowlisted path.
  if (!Buffer.isBuffer(data)) throw new Error('Expected raw Git diff bytes');
  const text = new TextDecoder('utf-8', { fatal: true }).decode(data);
  if (!text.endsWith('\0')) throw new Error('Empty or truncated Git diff');
  const fields = text.slice(0, -1).split('\0');
  const paths = [];
  for (let index = 0; index < fields.length;) {
    const status = fields[index++];
    if (!/^(?:[AMD]|R(?:100|[1-9]?\d))$/.test(status)) {
      throw new Error('Unknown Git diff status');
    }
    const count = status.startsWith('R') ? 2 : 1;
    for (let item = 0; item < count; item += 1) {
      const path = fields[index++];
      if (!path || /[\x00-\x1f\x7f\\]/.test(path) || path.startsWith('/') ||
          path.split('/').some(part => !part || part === '.' || part === '..')) {
        throw new Error('Invalid or incomplete Git diff path');
      }
      paths.push(path);
    }
  }
  return paths;
}

function classify(paths) {
  if (!Array.isArray(paths) || paths.length === 0) return full();
  const result = { python: false, ui: false, release: false };
  for (const path of paths) {
    const parts = path.split('/');
    // check-tracked-artifacts.py scans every tracked path, including docs/UI.
    // Preserve that global Python gate before any narrower source allowlist.
    if (parts.some(part => PYTHON_CACHE_NAMES.has(part) || part.endsWith('.egg-info'))) return full();
    // All workflow, dependency, build and toolchain inputs (including the
    // hash-locked build-requirements.txt) deliberately fall through to full.
    // This is an allowlist, so new directories/configuration cannot opt out.
    if (/(?:lock|requirements)/i.test(parts.at(-1))) return full();
    if (['README.md', 'SECURITY.md'].includes(path) ||
        /^docs\/(?:[^/]+\/)*[^/]+\.md$/.test(path) ||
        /^docs\/architecture\/generated\/[^/]+\.svg$/.test(path)) continue;

    if (/^memory_router\/.+\.(?:py|json)$/.test(path)) {
      // UI pretest/pretest:e2e -> ui/tests/gen_fixtures.py -> envelope,
      // key_wrap -> canonical/errors; runtime API contracts also feed the UI.
      // Keep the entire runtime closure instead of a fragile import list.
      result.python = result.ui = true;
    } else if (/^openapi\/[^/]+\.json$/.test(path)) {
      // Python contract tests read both schemas; UI runs Redocly against both.
      result.python = result.ui = true;
    } else if (path === 'ui/src/lib/types.ts') {
      // tests/test_review_reason_contract.py reads this file directly.
      result.python = result.ui = true;
    } else if (/^ui\/src\/.+\.(?:ts|tsx|css)$/.test(path) ||
        /^ui\/tests\/.+\.(?:ts|tsx|py|mjs)$/.test(path)) {
      // Includes the Python crypto fixture generator and package/e2e tests.
      result.ui = true;
    } else if (path.startsWith('tests/integration/')) {
      // Release failure-reporter tests execute smoke.sh's reporting functions.
      // Integration helpers also serve multiple container/Python gates.
      return full();
    } else if (/^tests\/.+\.py$/.test(path)) {
      result.python = true;
    } else {
      return full();
    }
  }
  // Security still scans the entire repository. Container/Hindsight still
  // run, including genuine Trivy SARIF required by code-scanning protection.
  return result;
}

function impact({ eventName, candidateSha = '', candidateRef = '', baseSha, headSha }, git = args =>
  execFileSync('git', args, { maxBuffer: 16 * 1024 * 1024, timeout: 30000 })) {
  if (eventName !== 'pull_request' || candidateSha || candidateRef) return full();
  try {
    if (![baseSha, headSha].every(sha => /^[a-f0-9]{40}$/.test(sha || ''))) return full();
    if (git(['rev-parse', '--is-shallow-repository']).toString().trim() !== 'false') return full();
    for (const sha of [baseSha, headSha]) git(['cat-file', '-e', `${sha}^{commit}`]);
    const bases = git(['merge-base', '--all', baseSha, headSha]).toString().trim().split('\n');
    if (bases.length !== 1 || !/^[a-f0-9]{40}$/.test(bases[0])) return full();
    // Local Git has no REST list-files (3000) or compare (300) file ceiling.
    // Buffer/time limits raise, never truncate into a successful smaller diff.
    const diff = git(['diff', '--no-ext-diff', '--no-textconv', '--name-status', '-z',
      '--find-renames', bases[0], headSha, '--']);
    return classify(parseDiff(diff));
  } catch {
    return full();
  }
}

module.exports = { classify, full, impact, parseDiff };
