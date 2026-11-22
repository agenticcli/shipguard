/**
 * json-text.ts: edit a JSON file AS TEXT, so every byte we do not mean to change stays as the user wrote it.
 *
 * `setup` appends its hook entry and `uninstall` cuts exactly that entry out again; in between nothing else is
 * re-serialised, so a hand-formatted `.claude/settings.json` (spaces inside braces, mixed lines, odd indents) comes
 * back byte for byte when ShipGuard's entry was the only change (QA e2e A-08). Plain strict JSON only (the same text
 * JSON.parse accepts); anything unexpected throws and the caller falls back to its re-serialising path.
 */

export interface JsonMember {
  key: string
  /** Start of the key's opening quote, end of the value. */
  start: number
  end: number
  value: JsonNode
}

export interface JsonNode {
  type: 'object' | 'array' | 'value'
  /** [start, end): for a container, start is the opening bracket and end is just after the closing one. */
  start: number
  end: number
  members: JsonMember[]
  items: JsonNode[]
}

const WS = /[ \t\r\n]/

/** Parse `text` into a tree that keeps the character span of every value. Throws on anything JSON.parse would reject. */
export function parseJsonSpans(text: string): JsonNode {
  let i = 0
  const skip = (): void => {
    while (i < text.length && WS.test(text[i])) i++
  }
  const fail = (what: string): never => {
    throw new Error(`json-text: ${what} at ${i}`)
  }
  const str = (): string => {
    const s = i
    if (text[i] !== '"') fail('expected a string')
    i++
    while (i < text.length && text[i] !== '"') i += text[i] === '\\' ? 2 : 1
    if (text[i] !== '"') fail('unterminated string')
    i++
    return JSON.parse(text.slice(s, i)) as string
  }
  const value = (): JsonNode => {
    skip()
    const start = i
    const c = text[i]
    if (c === '{') {
      i++
      const members: JsonMember[] = []
      skip()
      if (text[i] === '}') {
        i++
        return { type: 'object', start, end: i, members, items: [] }
      }
      for (;;) {
        skip()
        const mStart = i
        const key = str()
        skip()
        if (text[i] !== ':') fail('expected a colon')
        i++
        const v = value()
        members.push({ key, start: mStart, end: v.end, value: v })
        skip()
        if (text[i] === ',') {
          i++
          continue
        }
        if (text[i] === '}') {
          i++
          return { type: 'object', start, end: i, members, items: [] }
        }
        return fail('expected a comma or a closing brace')
      }
    }
    if (c === '[') {
      i++
      const items: JsonNode[] = []
      skip()
      if (text[i] === ']') {
        i++
        return { type: 'array', start, end: i, members: [], items }
      }
      for (;;) {
        items.push(value())
        skip()
        if (text[i] === ',') {
          i++
          continue
        }
        if (text[i] === ']') {
          i++
          return { type: 'array', start, end: i, members: [], items }
        }
        return fail('expected a comma or a closing bracket')
      }
    }
    if (c === '"') {
      str()
      return { type: 'value', start, end: i, members: [], items: [] }
    }
    while (i < text.length && !/[,\]}\s]/.test(text[i])) i++
    if (i === start) fail('expected a value')
    return { type: 'value', start, end: i, members: [], items: [] }
  }
  const root = value()
  skip()
  if (i !== text.length) fail('text after the value')
  return root
}

/** The last member with this key (JSON.parse keeps the last duplicate), or undefined. */
export function lastMember(node: JsonNode | undefined, key: string): JsonMember | undefined {
  if (!node || node.type !== 'object') return undefined
  for (let k = node.members.length - 1; k >= 0; k--) if (node.members[k].key === key) return node.members[k]
  return undefined
}

const spansOf = (c: JsonNode): Array<{ start: number; end: number }> => (c.type === 'object' ? c.members : c.items)

/**
 * Cut element `index` out of an object or array. The last element takes the comma before it; any other takes the
 * gap up to the next one; the only element empties the brackets. This is the exact inverse of appendToList.
 */
export function removeFromList(text: string, container: JsonNode, index: number): string {
  const els = spansOf(container)
  const n = els.length
  if (index < 0 || index >= n) throw new Error('json-text: no such element')
  if (n === 1) return text.slice(0, container.start + 1) + text.slice(container.end - 1)
  if (index === n - 1) return text.slice(0, els[n - 2].end) + text.slice(els[n - 1].end)
  return text.slice(0, els[index].start) + text.slice(els[index + 1].start)
}

/** What the file uses between elements, read from the file itself. */
export interface TextStyle {
  /** One indent step for a new nested level (used only when the file is multi-line). */
  unit: string
  /** The file is multi-line (an indent was found); an empty container then gets a multi-line body. */
  multiline: boolean
  crlf: boolean
}

/**
 * Append `value` (a member `"key": value` when `key` is given) as the last element of `container`, copying the gap
 * the file already puts between its elements. Inverse of removeFromList.
 */
export function appendToList(text: string, container: JsonNode, key: string | null, value: unknown, style: TextStyle): string {
  const els = spansOf(container)
  const n = els.length
  const nl = style.crlf ? '\r\n' : '\n'
  const body = (indent: string | null): string => {
    const rendered = indent === null ? JSON.stringify(value) : JSON.stringify(value, null, style.unit).replace(/\n/g, `\n${indent}`)
    const k = key === null ? '' : indent === null ? `${JSON.stringify(key)}:` : `${JSON.stringify(key)}: `
    return k + (style.crlf ? rendered.replace(/(?<!\r)\n/g, '\r\n') : rendered)
  }
  if (n === 0) {
    if (!style.multiline) return text.slice(0, container.start + 1) + body(null) + text.slice(container.start + 1)
    const lineStart = text.lastIndexOf('\n', container.start) + 1
    const base = /^[ \t]*/.exec(text.slice(lineStart))?.[0] ?? ''
    const inner = base + style.unit
    return text.slice(0, container.start + 1) + nl + inner + body(inner) + nl + base + text.slice(container.start + 1)
  }
  const gap = n >= 2 ? text.slice(els[n - 2].end, els[n - 1].start) : ',' + text.slice(container.start + 1, els[0].start)
  const nlAt = gap.lastIndexOf('\n')
  // Only the leading blanks count as indent (a comma-first file has `  , ` there).
  const indent = nlAt === -1 ? null : (/^[ \t]*/.exec(gap.slice(nlAt + 1))?.[0] ?? '')
  return text.slice(0, els[n - 1].end) + gap + body(indent) + text.slice(els[n - 1].end)
}
