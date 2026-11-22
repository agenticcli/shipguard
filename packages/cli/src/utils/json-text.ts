/** Edit a JSON file AS TEXT: only the bytes we add or cut change, so a hand-formatted settings.json round-trips exactly (e2e A-08). */

export interface JsonNode {
  type: 'object' | 'array' | 'value'
  /** [start, end); for a container start is the opening bracket. */
  start: number
  end: number
  /** Object members (key = "key": value, spanning key start to value end) or array items. */
  members: JsonMember[]
}

export interface JsonMember {
  key: string
  start: number
  end: number
  value: JsonNode
}

/** Parse `text` keeping every value's span. Throws on anything JSON.parse rejects. */
export function parseJsonSpans(text: string): JsonNode {
  let i = 0
  const ws = (): void => {
    while (i < text.length && ' \t\r\n'.includes(text[i])) i++
  }
  const bad = (): never => {
    throw new Error(`json-text: bad JSON at ${i}`)
  }
  const str = (): string => {
    const re = /"(?:[^"\\]|\\.)*"/y
    re.lastIndex = i
    const m = re.exec(text) ?? bad()
    i = re.lastIndex
    return JSON.parse(m[0]) as string
  }
  const value = (): JsonNode => {
    ws()
    const start = i
    const open = text[i]
    if (open === '{' || open === '[') {
      const type = open === '{' ? 'object' : 'array'
      const close = open === '{' ? '}' : ']'
      const members: JsonMember[] = []
      i++
      ws()
      if (text[i] === close) i++
      else {
        for (;;) {
          ws()
          const s = i
          const key = type === 'object' ? str() : ''
          if (type === 'object') {
            ws()
            if (text[i++] !== ':') bad()
          }
          const v = value()
          members.push({ key, start: s, end: v.end, value: v })
          ws()
          if (text[i] === ',') i++
          else if (text[i] === close) {
            i++
            break
          } else bad()
        }
      }
      return { type, start, end: i, members }
    }
    if (open === '"') str()
    else {
      while (i < text.length && !/[,\]}\s]/.test(text[i])) i++
      if (i === start) bad()
    }
    return { type: 'value', start, end: i, members: [] }
  }
  const root = value()
  ws()
  if (i !== text.length) bad()
  return root
}

/** The last member with this key (JSON.parse keeps the last duplicate). */
export function lastMember(node: JsonNode | undefined, key: string): JsonMember | undefined {
  return node?.type === 'object' ? [...node.members].reverse().find((m) => m.key === key) : undefined
}

/** Cut element `index`: the last takes the comma before it, another takes the gap up to the next, the only one empties the brackets. Inverse of appendToList. */
export function removeFromList(text: string, c: JsonNode, index: number): string {
  const els = c.members
  const n = els.length
  if (index < 0 || index >= n) throw new Error('json-text: no such element')
  if (n === 1) return text.slice(0, c.start + 1) + text.slice(c.end - 1)
  if (index === n - 1) return text.slice(0, els[n - 2].end) + text.slice(els[n - 1].end)
  return text.slice(0, els[index].start) + text.slice(els[index + 1].start)
}

export interface TextStyle {
  /** One indent step. */
  unit: string
  /** An empty container gets a multi-line body. */
  multiline: boolean
  crlf: boolean
}

/** Append `value` (as `"key": value` when key is given) after the last element, copying the file's own gap between elements. */
export function appendToList(text: string, c: JsonNode, key: string | null, value: unknown, style: TextStyle): string {
  const els = c.members
  const n = els.length
  const nl = style.crlf ? '\r\n' : '\n'
  const body = (indent: string | null): string => {
    const json = indent === null ? JSON.stringify(value) : JSON.stringify(value, null, style.unit).replace(/\n/g, `\n${indent}`)
    return (key === null ? '' : `${JSON.stringify(key)}:${indent === null ? '' : ' '}`) + (style.crlf ? json.replace(/(?<!\r)\n/g, '\r\n') : json)
  }
  if (n === 0) {
    if (!style.multiline) return text.slice(0, c.start + 1) + body(null) + text.slice(c.start + 1)
    const base = /^[ \t]*/.exec(text.slice(text.lastIndexOf('\n', c.start) + 1))?.[0] ?? ''
    return text.slice(0, c.start + 1) + nl + base + style.unit + body(base + style.unit) + nl + base + text.slice(c.start + 1)
  }
  const gap = n >= 2 ? text.slice(els[n - 2].end, els[n - 1].start) : ',' + text.slice(c.start + 1, els[0].start)
  const nlAt = gap.lastIndexOf('\n')
  // Only the leading blanks after the last newline are indent (a comma-first file has `  , ` there).
  const indent = nlAt === -1 ? null : /^[ \t]*/.exec(gap.slice(nlAt + 1))![0]
  return text.slice(0, els[n - 1].end) + gap + body(indent) + text.slice(els[n - 1].end)
}
