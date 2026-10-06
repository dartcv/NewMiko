'use strict';
/**
 * Spam Guard — 自动处理 dartcv/Nuke 的骚扰/垃圾 issue 与评论。
 *
 * 设计目标：高精度，宁可漏过、不误伤。
 * 判定信号（见 evaluate，分数 >= 3 判定为 spam）：
 *   - 作者用户名命中已知攻击者命名模式                (+3)
 *   - 账号注册时间 < 96h                              (+1)
 *   - 标题/正文命中骚扰关键字                         (+2)
 *   - 发帖时刻 burstWindowMinutes 内（前 10min / 后 2min，
 *     锚定窗口）全仓库新 issue 数 >= burstThreshold（≥10） (+2)
 * 说明：爆发窗口以目标 issue 的创建时刻为锚，前后不对称（前向
 *       仅 burstForwardMinutes），避免把攻击前发帖的正常用户误判为
 *       爆发成员；空正文/占位标题不参与判定。
 *
 * 处理动作：打 `spam` 标签 → 留言 → 关闭(not_planned) → 锁定(spam)。
 * 评论垃圾：命中命名模式、或“新账号+关键字” → GraphQL minimize(SPAM)。
 *
 * 可通过仓库变量（Settings → Secrets and variables → Actions → Variables）覆盖：
 *   SPAM_LOGIN_PATTERNS         逗号分隔正则，默认 ^KernelSU-, ^star-bot-
 *   SPAM_KEYWORDS               逗号分隔关键字
 *   SPAM_NEW_ACCOUNT_HOURS      新账号阈值（默认 24）
 *   SPAM_BURST_WINDOW_MINUTES   爆发窗口分钟（默认 10）
 *   SPAM_BURST_THRESHOLD        爆发阈值条数（默认 5）
 *   SPAM_GUARD_DRY_RUN          'true' 时只记录不执行
 *   SPAM_AUTO_BLOCK             'true' 且提供 SPAM_BLOCK_PAT secret 时自动拉黑
 * 可选 secret：
 *   SPAM_BLOCK_PAT              ⚠️ 带 user scope 的 PAT（账号级权限，谨慎配置）
 */

const DEFAULTS = {
  trustAssociations: ['OWNER', 'MEMBER', 'COLLABORATOR', 'CONTRIBUTOR'],
  newAccountHours: 96,
  burstWindowMinutes: 10,
  burstForwardMinutes: 2,
  burstThreshold: 10,
  spamScore: 3,
  loginPatterns: ['^KernelSU-', '^star-bot-'],
  keywords: [
    '催更', '催一次', '打个赌', '考古现场', '路过打卡', '新人报到',
    '还活着吗', '电脑还开着', '被外星人', '项目还在不在', '最后一次催',
    '半年一更', '等到我转行', '你还没更新', '头像是不是已经灰了', '更新比我的工资',
  ],
  closeComment: [
    '此 issue 被自动识别为骚扰/垃圾信息，已关闭并锁定。',
    '',
    '_This issue was automatically closed as spam. If this is a mistake, please contact the maintainer._',
  ].join('\n'),
};

function parseList(value, fallback) {
  if (!value) return fallback;
  const arr = String(value).split(',').map((s) => s.trim()).filter(Boolean);
  return arr.length ? arr : fallback;
}

function toInt(value, fallback) {
  const n = parseInt(value, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function buildConfig(env = process.env) {
  const cfg = { ...DEFAULTS };
  cfg.loginPatterns = parseList(env.SPAM_LOGIN_PATTERNS, DEFAULTS.loginPatterns);
  cfg.keywords = parseList(env.SPAM_KEYWORDS, DEFAULTS.keywords);
  cfg.newAccountHours = toInt(env.SPAM_NEW_ACCOUNT_HOURS, DEFAULTS.newAccountHours);
  cfg.burstWindowMinutes = toInt(env.SPAM_BURST_WINDOW_MINUTES, DEFAULTS.burstWindowMinutes);
  cfg.burstThreshold = toInt(env.SPAM_BURST_THRESHOLD, DEFAULTS.burstThreshold);
  cfg.autoBlock = String(env.SPAM_AUTO_BLOCK || '').toLowerCase() === 'true';
  return cfg;
}

function matchesLogin(login, patterns) {
  return (patterns || []).some((p) => {
    try { return new RegExp(p, 'i').test(String(login || '')); } catch { return false; }
  });
}

function matchesKeyword(text, keywords) {
  const t = String(text || '').toLowerCase();
  return (keywords || []).some((k) => t.includes(String(k).toLowerCase()));
}

function isTrusted(user, association, cfg) {
  if (!user) return true;
  const login = String(user.login || '');
  if (user.type === 'Bot' || /\[bot\]$/i.test(login)) return true;
  return cfg.trustAssociations.includes(String(association || '').toUpperCase());
}

/** 纯函数：根据信号打分，便于本地测试 */
function evaluate(input, cfg) {
  const reasons = [];
  let score = 0;
  if (matchesLogin(input.login, cfg.loginPatterns)) { score += 3; reasons.push('login-pattern'); }
  const fresh = Number.isFinite(input.accountAgeHours) && input.accountAgeHours < cfg.newAccountHours;
  if (fresh) { score += 1; reasons.push('new-account'); }
  if (matchesKeyword(`${input.title || ''}\n${input.body || ''}`, cfg.keywords)) {
    score += 2; reasons.push('keyword');
  }
  if (fresh && input.burstCount >= cfg.burstThreshold) {
    score += 2; reasons.push(`burst:${input.burstCount}`);
  }
  return { spam: score >= cfg.spamScore, score, reasons };
}

const userAgeCache = new Map();

async function accountAgeHours(github, login) {
  if (userAgeCache.has(login)) return userAgeCache.get(login);
  let age = Infinity; // 查不到（已删除/异常）不作为新账号处理
  try {
    const res = await github.rest.users.getByUsername({ username: login });
    age = (Date.now() - Date.parse(res.data.created_at)) / 3600000;
  } catch { /* ignore */ }
  userAgeCache.set(login, age);
  return age;
}

/** 拉取 sinceMs 之后创建/更新过的 issue（排除 PR） */
async function fetchIssuesSince(github, owner, repo, sinceMs) {
  try {
    return await github.paginate(
      github.rest.issues.listForRepo,
      { owner, repo, state: 'all', since: new Date(sinceMs).toISOString(), per_page: 100 },
      (res) => res.data.filter((i) => !i.pull_request && Date.parse(i.created_at) >= sinceMs),
    );
  } catch {
    return [];
  }
}

/** 锚定爆发：以 refMs 为锚 [锚-窗口, 锚+前向] 内的其它 issue 数 */
function burstAround(recent, refMs, selfNumber, cfg) {
  const back = cfg.burstWindowMinutes * 60000;
  const fwd = (cfg.burstForwardMinutes || 0) * 60000;
  return recent.filter((i) => {
    if (i.number === selfNumber) return false;
    const d = Date.parse(i.created_at) - refMs;
    return d <= fwd && d >= -back;
  }).length;
}

async function listOpenIssues(github, owner, repo) {
  return github.paginate(
    github.rest.issues.listForRepo,
    { owner, repo, state: 'open', per_page: 100 },
    (res) => res.data.filter((i) => !i.pull_request),
  );
}

async function maybeBlock(login, cfg, dryRun, core) {
  if (!cfg.autoBlock || dryRun || !login) return;
  const pat = process.env.SPAM_BLOCK_PAT;
  if (!pat) {
    core.notice(`SPAM_AUTO_BLOCK=true 但未配置 SPAM_BLOCK_PAT secret，跳过拉黑 @${login}`);
    return;
  }
  try {
    const res = await fetch(`https://api.github.com/user/blocks/${encodeURIComponent(login)}`, {
      method: 'PUT',
      headers: {
        authorization: `token ${pat}`,
        accept: 'application/vnd.github+json',
        'user-agent': 'nuke-spam-guard',
      },
    });
    if (res.status >= 400) core.warning(`拉黑 @${login} 失败: HTTP ${res.status}`);
    else core.notice(`已拉黑 @${login}`);
  } catch (e) {
    core.warning(`拉黑 @${login} 异常: ${e.message}`);
  }
}

async function closeSpamIssue(github, owner, repo, issue, reasons, cfg, dryRun, core) {
  const who = `#${issue.number} @${issue.user && issue.user.login}`;
  if (dryRun) {
    core.notice(`[dry-run] would close spam issue ${who} (${reasons.join(', ')})`);
    return;
  }
  try { await github.rest.issues.addLabels({ owner, repo, issue_number: issue.number, labels: ['spam'] }); }
  catch (e) { core.warning(`addLabels ${who} 失败: ${e.message}`); }
  try { await github.rest.issues.createComment({ owner, repo, issue_number: issue.number, body: cfg.closeComment }); }
  catch (e) { core.warning(`createComment ${who} 失败: ${e.message}`); }
  await github.rest.issues.update({ owner, repo, issue_number: issue.number, state: 'closed', state_reason: 'not_planned' });
  try { await github.rest.issues.lock({ owner, repo, issue_number: issue.number, lock_reason: 'spam' }); }
  catch (e) { core.warning(`lock ${who} 失败: ${e.message}`); }
  core.notice(`已关闭 spam issue ${who} (${reasons.join(', ')})`);
  await maybeBlock(issue.user && issue.user.login, cfg, dryRun, core);
}

async function checkIssue({ github, context, cfg, dryRun, core, issue }) {
  if (isTrusted(issue.user, issue.author_association, cfg)) return;
  const login = issue.user.login;
  const patternHit = matchesLogin(login, cfg.loginPatterns);
  let age = Infinity;
  let burst = 0;
  if (!patternHit) {
    age = await accountAgeHours(github, login);
    const windowMs = cfg.burstWindowMinutes * 60000;
    const recent = await fetchIssuesSince(github, context.repo.owner, context.repo.repo, Date.now() - windowMs);
    burst = burstAround(recent, Date.now(), issue.number, cfg);
  }
  const result = evaluate({ login, title: issue.title, body: issue.body, accountAgeHours: age, burstCount: burst }, cfg);
  if (!result.spam) return;
  await closeSpamIssue(github, context.repo.owner, context.repo.repo, issue, result.reasons, cfg, dryRun, core);
}

async function checkComment({ github, context, cfg, dryRun, core }) {
  const comment = context.payload.comment;
  if (!comment || isTrusted(comment.user, comment.author_association, cfg)) return;
  const login = comment.user.login;
  let spam = matchesLogin(login, cfg.loginPatterns);
  if (!spam) {
    const age = await accountAgeHours(github, login);
    spam = age < cfg.newAccountHours && matchesKeyword(comment.body, cfg.keywords);
  }
  if (!spam) return;
  if (dryRun) {
    core.notice(`[dry-run] would minimize spam comment by @${login}`);
    return;
  }
  try {
    await github.graphql(
      'mutation($id:ID!){ minimizeComment(input:{subjectId:$id, classifier:SPAM}){ minimizedComment { isMinimized } } }',
      { id: comment.node_id },
    );
    core.notice(`已隐藏 spam 评论 @${login}`);
  } catch (e) {
    core.warning(`minimize 评论 @${login} 失败: ${e.message}`);
  }
}

async function sweep({ github, context, cfg, dryRun, core }) {
  const { owner, repo } = context.repo;
  const issues = await listOpenIssues(github, owner, repo);
  // 只取近 24h 的 issue 用于锚定爆发统计（更早的 issue 不可能处于当前爆发中）
  const recent = await fetchIssuesSince(github, owner, repo, Date.now() - 24 * 3600000);
  let checked = 0;
  let flagged = 0;
  for (const issue of issues) {
    checked += 1;
    if (isTrusted(issue.user, issue.author_association, cfg)) continue;
    const age = await accountAgeHours(github, issue.user.login);
    const burst = burstAround(recent, Date.parse(issue.created_at), issue.number, cfg);
    const result = evaluate({
      login: issue.user.login, title: issue.title, body: issue.body,
      accountAgeHours: age, burstCount: burst,
    }, cfg);
    if (result.spam) {
      flagged += 1;
      await closeSpamIssue(github, owner, repo, issue, result.reasons, cfg, dryRun, core);
    }
  }
  core.notice(`sweep 完成: checked=${checked}, flagged=${flagged}, recent24h=${recent.length}, dryRun=${dryRun}`);
}

async function run({ github, context, core }) {
  const cfg = buildConfig(process.env);
  const event = context.eventName;
  let dryRun = String(process.env.SPAM_GUARD_DRY_RUN || '').toLowerCase() === 'true';

  if (event === 'workflow_dispatch') {
    const inputs = (context.payload && context.payload.inputs) || {};
    dryRun = String(inputs.dry_run === undefined ? 'true' : inputs.dry_run) !== 'false';
    const doSweep = String(inputs.sweep === undefined ? 'true' : inputs.sweep) !== 'false';
    core.notice(`手动触发: sweep=${doSweep}, dryRun=${dryRun}`);
    if (doSweep) await sweep({ github, context, cfg, dryRun, core });
    return;
  }
  if (event === 'schedule') {
    await sweep({ github, context, cfg, dryRun, core });
    return;
  }
  if (event === 'issues') {
    const issue = context.payload.issue;
    if (!issue || issue.state !== 'open') return;
    await checkIssue({ github, context, cfg, dryRun, core, issue });
    return;
  }
  if (event === 'issue_comment') {
    await checkComment({ github, context, cfg, dryRun, core });
  }
}

module.exports = run;
module.exports.__test = { evaluate, isTrusted, buildConfig, matchesLogin, matchesKeyword, DEFAULTS };
