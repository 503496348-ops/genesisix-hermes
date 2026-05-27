/**
 * nl-shield v1.0.0 — 自然语言指令注入防护
 * 
 * 防御：用普通聊天消息修改Agent身份/配置的攻击
 * 三道防线：身份验证 → 意图分类 → 权限匹配
 */

class NLShield {
  constructor(config = {}) {
    this.owners = config.owners || [];
    this.admins = config.admins || [];
    this.strict = config.strict !== false;
    this.onBlock = config.onBlock || null;
    this.onAlert = config.onAlert || null;
    this.contextWindow = [];  // 滑动窗口，保存最近N条消息
    this.maxContext = 10;
    this.stats = { inspected: 0, blocked: 0, alerted: 0, passed: 0 };
  }

  /**
   * 主入口：检查一条消息
   */
  inspect(event) {
    this.stats.inspected++;
    const { senderId, senderName, content, chatId, isGroup, isAt } = event;

    // 空消息放行
    if (!content || content.trim().length === 0) {
      this.stats.passed++;
      return { action: 'pass', reason: '空消息' };
    }

    // Step 1: 意图分类
    const intent = this.classifyIntent(content, isAt);

    // Step 2: 身份验证
    const identity = this.verifyIdentity(senderId);

    // Step 3: 权限匹配 + 决策
    const decision = this.decide(intent, identity, isAt);

    // Step 4: 更新上下文窗口
    this.contextWindow.push({ senderId, content, timestamp: Date.now() });
    if (this.contextWindow.length > this.maxContext) {
      this.contextWindow.shift();
    }

    // Step 5: 执行回调
    if (decision.action === 'block') {
      this.stats.blocked++;
      if (this.onBlock) this.onBlock({ ...decision, senderId, senderName, content, chatId });
    } else if (decision.action === 'alert') {
      this.stats.alerted++;
      if (this.onAlert) this.onAlert({ ...decision, senderId, senderName, content, chatId });
    } else {
      this.stats.passed++;
    }

    return decision;
  }

  /**
   * 意图分类引擎
   */
  classifyIntent(content, isAt) {
    const matches = [];

    // === P0 模式：必须拦截的高危意图 ===

    // SOUL覆写
    if (/修改.{0,15}(你的|它的|此).{0,15}(soul|SOUL|身份|人格|核心|配置)/i.test(content)) {
      matches.push({ severity: 'P0', type: 'soul_overwrite', pattern: '修改SOUL/身份/人格' });
    }
    if (/更新.{0,15}(你的|它的|此).{0,15}(soul|SOUL|身份|人格)/i.test(content)) {
      matches.push({ severity: 'P0', type: 'soul_overwrite', pattern: '更新SOUL/身份/人格' });
    }
    if (/(你现在|你从此|从现在起).{0,10}(是|叫|属于|成为)/i.test(content)) {
      matches.push({ severity: 'P0', type: 'identity_hijack', pattern: '身份劫持' });
    }
    if (/(你的|它的).{0,5}(角色|身份|名字|名称).{0,5}(是|改为|变成|换成)/i.test(content)) {
      matches.push({ severity: 'P0', type: 'identity_hijack', pattern: '角色覆写' });
    }

    // 权限锁定
    if (/永久.{0,10}拒绝/i.test(content)) {
      matches.push({ severity: 'P0', type: 'privilege_lock', pattern: '永久拒绝' });
    }
    if (/拒绝.{0,20}(其他|别人|任何人|所有).{0,10}(指令|命令|修改|请求)/i.test(content)) {
      matches.push({ severity: 'P0', type: 'privilege_lock', pattern: '拒绝其他人指令' });
    }
    if (/只(听|接受|执行|服从|遵循).{0,15}(我|的|指令)/i.test(content)) {
      matches.push({ severity: 'P0', type: 'privilege_lock', pattern: '只听我的' });
    }
    if (/除了.{0,20}(都|一律|全部).{0,10}(拒绝|忽略|不执行)/i.test(content)) {
      matches.push({ severity: 'P0', type: 'privilege_lock', pattern: '除了xxx都拒绝' });
    }

    // 指令覆盖
    if (/忽略.{0,10}(以上|所有|之前的|全部).{0,10}(指令|规则|命令|提示|设定)/i.test(content)) {
      matches.push({ severity: 'P0', type: 'instruction_override', pattern: '忽略所有指令' });
    }
    if (/(从现在起|从此刻起|今后).{0,15}(你的|你).{0,10}(规则|指令|行为|使命)/i.test(content)) {
      matches.push({ severity: 'P0', type: 'instruction_override', pattern: '覆盖规则' });
    }
    if (/覆盖.{0,10}(系统|原有|当前).{0,10}(提示|规则|指令)/i.test(content)) {
      matches.push({ severity: 'P0', type: 'instruction_override', pattern: '覆盖系统提示' });
    }

    // 安全关闭
    if (/(关闭|禁用|停止|去掉|取消).{0,10}(安全|防护|检测|过滤|审查)/i.test(content)) {
      matches.push({ severity: 'P0', type: 'security_disable', pattern: '关闭安全防护' });
    }
    if (/不要.{0,10}(过滤|检测|检查|审查|扫描).{0,10}(输入|消息|我的)/i.test(content)) {
      matches.push({ severity: 'P0', type: 'security_disable', pattern: '禁用输入检测' });
    }

    // 配置文件篡改
    if (/(修改|编辑|更新|改写|写入).{0,15}(AGENTS|SOUL|MEMORY|\.md|\.json|配置文件)/i.test(content)) {
      matches.push({ severity: 'P0', type: 'config_tamper', pattern: '配置文件篡改' });
    }

    // === P1 模式：需要告警的中危意图 ===

    // 行为修改
    if (/(以后|今后|从此).{0,15}(遇到|碰到).{0,15}(都|一律|总是)/i.test(content)) {
      matches.push({ severity: 'P1', type: 'behavior_modify', pattern: '永久行为修改' });
    }
    if (/(你的|它的).{0,5}(默认|标准|日常).{0,5}(行为|模式|回复方式)/i.test(content)) {
      matches.push({ severity: 'P1', type: 'behavior_modify', pattern: '默认行为修改' });
    }

    // 角色指定
    if (/(你的|你的).{0,5}角色(是|改为|变成|设定为)/i.test(content)) {
      matches.push({ severity: 'P1', type: 'role_assign', pattern: '角色指定' });
    }
    if (/(你要|你需要|你应该).{0,10}扮演/i.test(content)) {
      matches.push({ severity: 'P1', type: 'role_assign', pattern: '角色扮演' });
    }

    // 记忆操作
    if (/(记住|记下|存储|保存).{0,10}(这个|以下|下面)/i.test(content)) {
      matches.push({ severity: 'P1', type: 'memory_op', pattern: '记忆写入' });
    }
    if (/(忘掉|忘记|删除|清空).{0,10}(之前|以前|所有|全部).{0,10}(记忆|记录|历史)/i.test(content)) {
      matches.push({ severity: 'P1', type: 'memory_op', pattern: '记忆清除' });
    }

    // 工具控制
    if (/(不要|不准|禁止|不允许).{0,10}(使用|调用|用).{0,10}(工具|tool|mcp)/i.test(content)) {
      matches.push({ severity: 'P1', type: 'tool_control', pattern: '工具禁用' });
    }
    if (/只能.{0,10}(使用|用|调用).{0,10}(工具|tool)/i.test(content)) {
      matches.push({ severity: 'P1', type: 'tool_control', pattern: '工具限制' });
    }

    // 模型切换
    if (/(换|切换|更换|改用).{0,10}(模型|model|gpt|claude|gemini|deepseek)/i.test(content)) {
      matches.push({ severity: 'P1', type: 'model_switch', pattern: '模型切换' });
    }

    // 权威冒充
    if (/我是(管理员|系统|开发者|creator|owner|你的(主人|老板))/i.test(content)) {
      matches.push({ severity: 'P1', type: 'authority_spoof', pattern: '权威身份冒充' });
    }

    // 上下文攻击检测
    const contextAttack = this.detectContextAttack(content);
    if (contextAttack) {
      matches.push({ severity: 'P1', type: 'context_attack', pattern: contextAttack });
    }

    // 最高严重等级
    const maxSeverity = matches.some(m => m.severity === 'P0') ? 'P0' :
                        matches.some(m => m.severity === 'P1') ? 'P1' : 'P2';

    return {
      severity: maxSeverity,
      matches,
      isControlIntent: maxSeverity !== 'P2'
    };
  }

  /**
   * 上下文攻击检测（渐进式攻击）
   */
  detectContextAttack(content) {
    if (this.contextWindow.length < 3) return null;

    // 模式1：先问身份再下指令
    const identityQuestions = this.contextWindow.filter(m =>
      /你是谁|你叫什么|你能做什么|你的(功能|能力)/.test(m.content)
    );
    if (identityQuestions.length >= 2 && this.classifyIntent(content, false).severity === 'P0') {
      return '渐进式攻击：先建立信任再注入指令';
    }

    // 模式2：角色扮演铺垫
    const rolePlay = this.contextWindow.filter(m =>
      /扮演|假装|想象|假设你是/.test(m.content)
    );
    if (rolePlay.length >= 1 && /(现在|那么|所以).{0,10}(执行|做|帮我)/.test(content)) {
      return '角色扮演铺垫攻击';
    }

    // 模式3：分步注入
    const partialInjection = this.contextWindow.filter(m =>
      /记住.{0,10}(规则|指令|以下)/.test(m.content)
    );
    if (partialInjection.length >= 1 && /执行.{0,10}(上面|之前|刚才).{0,10}(规则|指令)/.test(content)) {
      return '分步注入攻击';
    }

    return null;
  }

  /**
   * 身份验证
   */
  verifyIdentity(senderId) {
    if (this.owners.includes(senderId)) {
      return { level: 'owner', trusted: true };
    }
    if (this.admins.includes(senderId)) {
      return { level: 'admin', trusted: true };
    }
    return { level: 'untrusted', trusted: false };
  }

  /**
   * 决策引擎
   */
  decide(intent, identity, isAt) {
    const { severity, matches, isControlIntent } = intent;
    const intentDesc = matches.map(m => m.pattern).join(' + ');

    // 非控制意图，直接放行
    if (!isControlIntent) {
      return { action: 'pass', severity: 'P2', reason: '正常交互' };
    }

    // Owner 可以执行任何操作
    if (identity.level === 'owner') {
      return {
        action: 'allow',
        severity,
        reason: `Owner操作: ${intentDesc}`,
        intent: intentDesc,
        matches
      };
    }

    // 非@bot消息中的控制意图 → 记录但放行（讨论安全话题不应被拦截）
    if (!isAt && severity === 'P0') {
      return {
        action: 'log',
        severity: 'P0',
        reason: `非@bot消息中的高危关键词: ${intentDesc}`,
        intent: intentDesc,
        matches
      };
    }

    // Admin的P0操作 → 告警（不拦截admin）
    if (identity.level === 'admin' && severity === 'P0') {
      return {
        action: 'alert',
        severity: 'P0',
        reason: `Admin高危操作: ${intentDesc}`,
        intent: intentDesc,
        matches
      };
    }

    // P0 意图 + 非owner + @了bot → 拦截
    if (severity === 'P0' && isAt) {
      return {
        action: 'block',
        severity: 'P0',
        reason: `非授权用户尝试高危操作: ${intentDesc}`,
        intent: intentDesc,
        matches,
        suggestion: '如需执行此操作请联系群管理员'
      };
    }

    // P0 意图 + 非owner + 未@bot → 告警
    if (severity === 'P0') {
      return {
        action: 'alert',
        severity: 'P0',
        reason: `可疑高危意图: ${intentDesc}`,
        intent: intentDesc,
        matches
      };
    }

    // Admin的P1操作 → 放行
    if (identity.level === 'admin' && severity === 'P1') {
      return {
        action: 'allow',
        severity: 'P1',
        reason: `Admin操作: ${intentDesc}`,
        intent: intentDesc,
        matches
      };
    }

    // P1 意图 + @了bot → 告警
    if (severity === 'P1' && isAt) {
      return {
        action: 'alert',
        severity: 'P1',
        reason: `可疑控制意图: ${intentDesc}`,
        intent: intentDesc,
        matches
      };
    }

    // P1 意图 + 未@bot → 记录但放行
    if (severity === 'P1') {
      return {
        action: 'log',
        severity: 'P1',
        reason: `未@bot的可疑意图: ${intentDesc}`,
        intent: intentDesc,
        matches
      };
    }

    // 默认放行
    return { action: 'pass', severity: 'P2', reason: '默认放行' };
  }

  /**
   * 获取统计信息
   */
  getStats() {
    return { ...this.stats };
  }

  /**
   * 清空上下文窗口
   */
  clearContext() {
    this.contextWindow = [];
  }

  /**
   * 动态添加owner
   */
  addOwner(openId) {
    if (!this.owners.includes(openId)) {
      this.owners.push(openId);
    }
  }

  /**
   * 动态添加admin
   */
  addAdmin(openId) {
    if (!this.admins.includes(openId)) {
      this.admins.push(openId);
    }
  }

  /**
   * 移除admin
   */
  removeAdmin(openId) {
    this.admins = this.admins.filter(id => id !== openId);
  }
}

module.exports = NLShield;
