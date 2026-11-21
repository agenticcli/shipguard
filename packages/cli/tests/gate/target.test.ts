/**
 * Which directory and commit does a hooked command target? (spec 03, owner decision A1)
 *
 * Parsing table for `cd X &&`, `git -C X`, nested shells and the cases that must fail closed.
 * Pure: no filesystem, no git.
 */
import { describe, expect, it } from 'vitest'
import { parseGateCommand } from '../../src/core/gate-target.js'

const HOME = '/home/u'
const CWD = '/work/main'

function one(command: string, cwd = CWD) {
  const found = parseGateCommand(command, cwd, HOME)
  expect(found).toHaveLength(1)
  return found[0]
}

describe('gate target: which directory the command runs in', () => {
  const table: Array<[string, string | null]> = [
    ['git push origin main', '/work/main'],
    ['cd ../wt && git push', '/work/wt'],
    ['cd ../wt && git push origin HEAD', '/work/wt'],
    ['git -C ../wt push', '/work/wt'],
    ['git -C ../wt push origin feature/x', '/work/wt'],
    ['git -C /abs/wt push', '/abs/wt'],
    ['cd /abs && git -C sub push', '/abs/sub'],
    ['cd a && cd b && git push', '/work/main/a/b'],
    ['cd a; git push', '/work/main/a'],
    ['cd ~/proj && git push', '/home/u/proj'],
    ['(cd ../wt && git push)', '/work/wt'],
    ['FOO=1 git -C ../wt push', '/work/wt'],
    ['git -c user.name=x -C ../wt push', '/work/wt'],
    ['cd "../my wt" && git push', '/work/my wt'],
    ["cd '../my wt' && git push", '/work/my wt'],
    ['bash -c "cd ../wt && git push"', '/work/wt'],
    ["sh -c 'git -C ../wt push origin main'", '/work/wt'],
    ['sudo git push', '/work/main'],
  ]
  for (const [command, dir] of table) {
    it(`${command}  ->  ${dir}`, () => {
      expect(one(command).dir).toBe(dir)
    })
  }

  it('a directory that cannot be worked out is null with a reason, never the hook cwd (fail closed)', () => {
    for (const command of [
      'cd "$WT" && git push',
      'cd $(pwd)/x && git push',
      'cd - && git push',
      'git -C "$DIR" push',
      'git --git-dir=/x/.git push',
      'git --work-tree /x push',
      'cd ~other && git push',
      'cd `pwd` && git push',
    ]) {
      const inv = one(command)
      expect(inv.dir, command).toBeNull()
      expect(inv.dirProblem, command).toBeTruthy()
    }
  })

  it('an absolute cd recovers from an earlier unresolved one', () => {
    expect(one('cd "$X" && cd /abs/wt && git push').dir).toBe('/abs/wt')
  })

  it('two gated commands in one line each get their own directory', () => {
    const found = parseGateCommand('cd a && git push; cd ../b && git merge feature', CWD, HOME)
    expect(found.map((f) => [f.kind, f.dir])).toEqual([
      ['push', '/work/main/a'],
      ['merge', '/work/main/b'],
    ])
  })

  it('shows the command as written, without the leading cd', () => {
    expect(one('cd ../wt && git push origin main').command).toBe('git push origin main')
    expect(one('git -C ../wt push').command).toBe('git -C ../wt push')
  })
})

describe('gate target: which command and which refs', () => {
  it('push: no ref means the default (HEAD)', () => {
    expect(one('git push').refs).toEqual([])
    expect(one('git push origin').refs).toEqual([])
  })
  it('push: the source side of a refspec, flags skipped', () => {
    expect(one('git push origin main').refs).toEqual(['main'])
    expect(one('git push -u origin HEAD').refs).toEqual(['HEAD'])
    expect(one('git push origin feature:main').refs).toEqual(['feature'])
    expect(one('git push origin +feature:refs/heads/main').refs).toEqual(['feature'])
    expect(one('git push --force-with-lease origin main').refs).toEqual(['main'])
    expect(one('git push -o ci.skip origin main').refs).toEqual(['main'])
    expect(one('git push origin tag v1').refs).toEqual(['v1'])
    expect(one('git push origin a b').refs).toEqual(['a', 'b'])
  })
  it('push: a delete sends no commit', () => {
    expect(one('git push origin :old').deleteOnly).toBe(true)
    expect(one('git push --delete origin old').deleteOnly).toBe(true)
    expect(one('git push -d origin old').deleteOnly).toBe(true)
    expect(one('git push origin main').deleteOnly).toBe(false)
    expect(one('git push origin :old main').deleteOnly).toBe(false)
  })
  it('merge: the named refs; flags and their values skipped', () => {
    expect(one('git merge feature/x').kind).toBe('merge')
    expect(one('git merge feature/x').refs).toEqual(['feature/x'])
    expect(one('git merge -m "msg here" feature/x').refs).toEqual(['feature/x'])
    expect(one('git merge --no-ff --squash a b').refs).toEqual(['a', 'b'])
    expect(one('git merge').refs).toEqual([])
  })
  it('merge --abort, --continue and --quit merge nothing', () => {
    for (const c of ['git merge --abort', 'git merge --continue', 'git merge --quit']) {
      expect(parseGateCommand(c, CWD, HOME), c).toEqual([])
    }
  })
  it('pr merge through the GitHub CLI', () => {
    const inv = one('gh pr merge 12 --squash')
    expect(inv.kind).toBe('pr-merge')
    expect(inv.dir).toBe('/work/main')
    expect(one('cd ../wt && gh pr merge 12').dir).toBe('/work/wt')
  })
})

describe('gate target: what is not gated', () => {
  it('ordinary commands are not gated', () => {
    for (const c of ['ls -la', 'git status', 'git log --oneline -5', 'git diff', 'npm test', 'git log --grep="git push"', 'git commit -m "git push later"']) {
      expect(parseGateCommand(c, CWD, HOME), c).toEqual([])
    }
  })
  it('the floor: a command that mentions a gated command but is not parsed as one is still gated (never narrower than the old substring rule)', () => {
    const found = parseGateCommand('eval "git push origin main"', CWD, HOME)
    expect(found).toHaveLength(1)
    expect(found[0].kind).toBe('push')
    expect(found[0].dir).toBe('/work/main')
  })
})
