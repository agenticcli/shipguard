// Test-only preload (NODE_OPTIONS=--require): removes the scan folder (env SG_VANISH_DIR) the first
// time the scanner stats a file under <dir>/src, i.e. while the scan is running. Reproduces a scan
// folder deleted mid-scan (bug: the scan spun forever in a relative recursive mkdir).
const fs = require('node:fs')
const fsp = fs.promises
const dir = process.env.SG_VANISH_DIR
const orig = fsp.stat
let done = false
fsp.stat = function (p, ...rest) {
  if (!done && dir && String(p).startsWith(dir + '/src')) {
    done = true
    fs.rmSync(dir, { recursive: true, force: true })
  }
  return orig.call(this, p, ...rest)
}
