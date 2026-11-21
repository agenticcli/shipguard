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
      'git --git-dir=/x/bare.git push',
      'GIT_DIR=/x/bare.git git push',
      'cd ~other && git push',
      'cd `pwd` && git push',
    ]) {
      const inv = one(command)
      expect(inv.dir, command).toBeNull()
      expect(inv.dirProblem, command).toBeTruthy()
    }
  })

  it('an unknown launcher or a shell construct in front of git keeps the directory state: a bad cd is never forgotten (false SAFE otherwise)', () => {
    for (const command of [
      'cd "$BAD"; timeout 60 git push',
      'cd "$BAD" && xargs git push',
      'cd "$BAD" && stdbuf -o0 git push',
      'if cd "$BAD"; then git push; fi',
      'cd "$BAD"; for r in origin; do git push $r main; done',
      'cd "$BAD"; eval "git push origin main"',
      'cd /nonexistent-ok && cd "$BAD" && while true; do git push; done',
    ]) {
      const found = parseGateCommand(command, CWD, HOME)
      expect(found.length, command).toBeGreaterThan(0)
      for (const inv of found) {
        expect(inv.dir, command).toBeNull()
        expect(inv.dirProblem, command).toBeTruthy()
      }
    }
  })

  it('the same forms with a good cd run where the cd says', () => {
    for (const command of ['cd ../wt && timeout 60 git push', 'cd ../wt; xargs git push', 'if cd ../wt; then git push; fi', 'cd ../wt && eval "git push"']) {
      const found = parseGateCommand(command, CWD, HOME)
      expect(found.length, command).toBeGreaterThan(0)
      expect(found.every((f) => f.dir === '/work/wt'), command).toBe(true)
    }
  })

  it('push --all, --mirror and --tags are flagged: the push sends more than the named refs', () => {
    expect(one('git push --all origin').allRefs).toBe('heads')
    expect(one('git push --mirror').allRefs).toBe('all')
    expect(one('git push --tags').allRefs).toBe('tags')
    expect(one('git push --all --tags').allRefs).toBe('all')
    expect(one("git push origin 'refs/heads/*:refs/heads/*'").allRefs).toBe('heads')
    expect(one('git push origin refs/tags/*').allRefs).toBe('tags')
    expect(one('git push origin +refs/*:refs/*').allRefs).toBe('all')
    expect(one('git push origin main').allRefs).toBeUndefined()
  })

  it('GIT_DIR, GIT_WORK_TREE, --git-dir, --work-tree and env -C name the repository the push acts on (never the hook cwd)', () => {
    const table: Array<[string, string]> = [
      ['GIT_DIR=/x/.git git push', '/x'],
      ['GIT_DIR=../wt/.git git push', '/work/wt'],
      ['GIT_WORK_TREE=/y GIT_DIR=/x/.git git push', '/y'],
      ['export GIT_DIR=/x/.git; git push', '/x'],
      ['GIT_DIR=/x/.git; git push', '/x'],
      ['git --git-dir=/x/.git push', '/x'],
      ['git --git-dir /x/.git --work-tree /y push', '/y'],
      ['env GIT_DIR=/x/.git git push', '/x'],
      ['env -C ../wt git push', '/work/wt'],
      ['env --chdir=../wt git push', '/work/wt'],
      ['env -i -C /abs FOO=1 git push', '/abs'],
      ['cd /a && env -C b git push', '/a/b'],
    ]
    for (const [command, dir] of table) expect(one(command).dir, command).toBe(dir)
    // env -C applies to that command only
    const two = parseGateCommand('env -C ../wt git push; git push', CWD, HOME)
    expect(two.map((x) => x.dir)).toEqual(['/work/wt', '/work/main'])
    // unset clears it
    expect(one('export GIT_DIR=/x/.git; unset GIT_DIR; git push').dir).toBe('/work/main')
  })

  it('floor: a command the parser cannot place is gated as a push of the directory, never waved through', () => {
    for (const command of [
      '/usr/bin/g[i]t push origin main',
      '/usr/bin/g?t push',
      'G=git; $G push origin main',
      '$(echo git) push',
      'eval "g""it push origin main"',
      'eval "$CMD"',
      'git p',
      'git ps origin main',
      'cd ../wt && $G push',
    ]) {
      const found = parseGateCommand(command, CWD, HOME)
      expect(found.length, command).toBeGreaterThan(0)
      expect(found[0].kind, command).toBe('push')
    }
    expect(one('cd ../wt && $G push').dir).toBe('/work/wt')
    expect(one('cd "$BAD"; $G push').dir).toBeNull()
    const split = parseGateCommand('env -S "git push"', CWD, HOME)
    expect(split).toHaveLength(1)
    expect(split[0].dir).toBeNull()
  })

  it('floor: commands that are positively not a push stay silent', () => {
    for (const command of ['ls -la', 'npm test', 'docker push image', 'git status', 'git stash push', 'git log -3', 'git commit -m x', 'FOO=1 make', '[ -f x ] && echo y', 'echo done', './deploy.sh', 'git --version', 'git']) {
      expect(parseGateCommand(command, CWD, HOME), command).toEqual([])
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
