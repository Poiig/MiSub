import yaml from 'js-yaml';
import { StorageFactory, DataMigrator, STORAGE_TYPES } from './storage-adapter.js';

/**
 * 将 Clash 代理对象转换为标准节点链接
 * @param {Object} proxy - Clash 代理对象
 * @returns {string|null} - 节点链接或 null
 */
function clashProxyToNodeLink(proxy) {
    try {
        const { name, server, port, type, cipher, password, uuid, tls, network, 'ws-opts': wsOpts } = proxy;

        if (!server || !port) return null;

        // Shadowsocks
        if (type === 'ss') {
            if (!cipher || !password) return null;
            const auth = `${cipher}:${password}`;
            const encoded = btoa(auth);
            const nodeName = encodeURIComponent(name || 'SS Node');
            return `ss://${encoded}@${server}:${port}#${nodeName}`;
        }

        // VMess
        if (type === 'vmess') {
            const vmessConfig = {
                v: '2',
                ps: name || 'VMess Node',
                add: server,
                port: String(port),
                id: uuid || '',
                aid: String(proxy.alterId || 0),
                scy: proxy.cipher || 'auto',
                net: network || 'tcp',
                type: 'none',
                host: '',
                path: '',
                tls: tls ? 'tls' : ''
            };

            if (network === 'ws' && wsOpts) {
                vmessConfig.host = wsOpts.headers?.Host || '';
                vmessConfig.path = wsOpts.path || '';
            }

            const vmessJson = JSON.stringify(vmessConfig);
            const encoded = btoa(unescape(encodeURIComponent(vmessJson)));
            return `vmess://${encoded}`;
        }

        // Trojan
        if (type === 'trojan') {
            if (!password) return null;
            const nodeName = encodeURIComponent(name || 'Trojan Node');
            const tlsParam = tls === false ? '' : '?security=tls';
            return `trojan://${password}@${server}:${port}${tlsParam}#${nodeName}`;
        }

        // 其他类型暂不支持
        return null;
    } catch (e) {
        console.error('[clashProxyToNodeLink] 转换失败:', e.message);
        return null;
    }
}

/**
 * 从 Clash YAML 配置中提取节点
 * @param {string} yamlText - YAML 文本内容
 * @returns {string[]} - 节点链接数组
 */
function extractNodesFromClashYAML(yamlText) {
    try {
        const config = yaml.load(yamlText);

        if (!config || !config.proxies || !Array.isArray(config.proxies)) {
            return [];
        }

        const nodes = [];
        for (const proxy of config.proxies) {
            const nodeLink = clashProxyToNodeLink(proxy);
            if (nodeLink) {
                nodes.push(nodeLink);
            }
        }

        console.log(`[extractNodesFromClashYAML] 从 Clash 配置中提取了 ${nodes.length} 个节点`);
        return nodes;
    } catch (e) {
        console.error('[extractNodesFromClashYAML] YAML 解析失败:', e.message);
        return [];
    }
}

/**
 * 修复Clash配置中的WireGuard问题
 * @param {string} content - Clash配置内容
 * @returns {string} - 修复后的配置内容
 */
function clashFix(content) {
    if (content.includes('wireguard') && !content.includes('remote-dns-resolve')) {
        let lines;
        if (content.includes('\r\n')) {
            lines = content.split('\r\n');
        } else {
            lines = content.split('\n');
        }

        let result = "";
        for (let line of lines) {
            if (line.includes('type: wireguard')) {
                const 备改内容 = `, mtu: 1280, udp: true`;
                const 正确内容 = `, mtu: 1280, remote-dns-resolve: true, udp: true`;
                result += line.replace(new RegExp(备改内容, 'g'), 正确内容) + '\n';
            } else {
                result += line + '\n';
            }
        }
        return result;
    }
    return content;
}

const OLD_KV_KEY = 'misub_data_v1';
const KV_KEY_SUBS = 'misub_subscriptions_v1';
const KV_KEY_PROFILES = 'misub_profiles_v1';
const KV_KEY_SETTINGS = 'worker_settings_v1';
const COOKIE_NAME = 'auth_session';
const SESSION_DURATION = 8 * 60 * 60 * 1000;

/**
 * 计算数据的简单哈希值，用于检测变更
 * @param {any} data - 要计算哈希的数据
 * @returns {string} - 数据的哈希值
 */
function calculateDataHash(data) {
    const jsonString = JSON.stringify(data, Object.keys(data).sort());
    let hash = 0;
    for (let i = 0; i < jsonString.length; i++) {
        const char = jsonString.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // 转换为32位整数
    }
    return hash.toString();
}

/**
 * 检测数据是否发生变更
 * @param {any} oldData - 旧数据
 * @param {any} newData - 新数据
 * @returns {boolean} - 是否发生变更
 */
function hasDataChanged(oldData, newData) {
    if (!oldData && !newData) return false;
    if (!oldData || !newData) return true;
    return calculateDataHash(oldData) !== calculateDataHash(newData);
}

/**
 * 条件性写入KV存储，只在数据真正变更时写入
 * @param {Object} env - Cloudflare环境对象
 * @param {string} key - KV键名
 * @param {any} newData - 新数据
 * @param {any} oldData - 旧数据（可选）
 * @returns {Promise<boolean>} - 是否执行了写入操作
 */
async function conditionalKVPut(env, key, newData, oldData = null) {
    // 如果没有提供旧数据，先从KV读取
    if (oldData === null) {
        try {
            oldData = await env.MISUB_KV.get(key, 'json');
        } catch (error) {
            // 读取失败时，为安全起见执行写入
            await env.MISUB_KV.put(key, JSON.stringify(newData));
            return true;
        }
    }

    // 检测数据是否变更
    if (hasDataChanged(oldData, newData)) {
        await env.MISUB_KV.put(key, JSON.stringify(newData));
        return true;
    } else {
        return false;
    }
}

// {{ AURA-X: Add - 批量写入优化机制. Approval: 寸止(ID:1735459200). }}
/**
 * 批量写入队列管理器
 */
class BatchWriteManager {
    constructor() {
        this.writeQueue = new Map(); // key -> {data, timestamp, resolve, reject}
        this.debounceTimers = new Map(); // key -> timerId
        this.DEBOUNCE_DELAY = 1000; // 1秒防抖延迟
    }

    /**
     * 添加写入任务到队列，使用防抖机制
     * @param {Object} env - Cloudflare环境对象
     * @param {string} key - KV键名
     * @param {any} data - 要写入的数据
     * @param {any} oldData - 旧数据（用于变更检测）
     * @returns {Promise<boolean>} - 是否执行了写入
     */
    async queueWrite(env, key, data, oldData = null) {
        return new Promise((resolve, reject) => {
            // 清除之前的定时器
            if (this.debounceTimers.has(key)) {
                clearTimeout(this.debounceTimers.get(key));
            }

            // 更新队列中的数据
            this.writeQueue.set(key, {
                data,
                oldData,
                timestamp: Date.now(),
                resolve,
                reject
            });

            // 设置新的防抖定时器
            const timerId = setTimeout(async () => {
                await this.executeWrite(env, key);
            }, this.DEBOUNCE_DELAY);

            this.debounceTimers.set(key, timerId);
        });
    }

    /**
     * 执行实际的写入操作
     * @param {Object} env - Cloudflare环境对象
     * @param {string} key - KV键名
     */
    async executeWrite(env, key) {
        const writeTask = this.writeQueue.get(key);
        if (!writeTask) return;

        // 清理定时器
        if (this.debounceTimers.has(key)) {
            clearTimeout(this.debounceTimers.get(key));
            this.debounceTimers.delete(key);
        }

        try {
            const wasWritten = await conditionalKVPut(env, key, writeTask.data, writeTask.oldData);
            writeTask.resolve(wasWritten);
        } catch (error) {
            writeTask.reject(error);
        } finally {
            // 清理队列
            this.writeQueue.delete(key);
        }
    }

    /**
     * 立即执行所有待写入的任务（用于紧急情况）
     * @param {Object} env - Cloudflare环境对象
     */
    async flushAll(env) {
        const keys = Array.from(this.writeQueue.keys());
        const promises = keys.map(key => this.executeWrite(env, key));
        await Promise.allSettled(promises);
    }
}

// 全局批量写入管理器实例
const batchWriteManager = new BatchWriteManager();

/**
 * 获取存储适配器实例
 * @param {Object} env - Cloudflare 环境对象
 * @returns {Promise<Object>} 存储适配器实例
 */
async function getStorageAdapter(env) {
    const storageType = await StorageFactory.getStorageType(env);
    return StorageFactory.createAdapter(env, storageType);
}

/**
 * 处理配置的向后兼容性，确保新的前缀配置结构存在
 * @param {Object} config - 原始配置对象
 * @returns {Object} - 处理后的配置对象
 */
function migrateConfigSettings(config) {
    const migratedConfig = { ...config };

    // 如果没有新的 prefixConfig，但有老的 prependSubName，则创建默认的 prefixConfig
    if (!migratedConfig.prefixConfig) {
        const fallbackEnabled = migratedConfig.prependSubName ?? true;
        migratedConfig.prefixConfig = {
            enableManualNodes: fallbackEnabled,
            enableSubscriptions: fallbackEnabled,
            manualNodePrefix: '手动节点'
        };
    }

    // 确保 prefixConfig 的所有字段都存在
    if (!migratedConfig.prefixConfig.hasOwnProperty('enableManualNodes')) {
        migratedConfig.prefixConfig.enableManualNodes = migratedConfig.prependSubName ?? true;
    }
    if (!migratedConfig.prefixConfig.hasOwnProperty('enableSubscriptions')) {
        migratedConfig.prefixConfig.enableSubscriptions = migratedConfig.prependSubName ?? true;
    }
    if (!migratedConfig.prefixConfig.hasOwnProperty('manualNodePrefix')) {
        migratedConfig.prefixConfig.manualNodePrefix = '手动节点';
    }

    return migratedConfig;
}

// --- [新] 默认设置中增加通知阈值和存储类型 ---
const defaultSettings = {
    FileName: 'MiSub',
    mytoken: 'auto',
    profileToken: 'profiles',
    subConverter: 'url.v1.mk',
    subConfig: 'https://raw.githubusercontent.com/cmliu/ACL4SSR/refs/heads/main/Clash/config/ACL4SSR_Online_Full.ini',
    prependSubName: true, // 保持向后兼容
    prefixConfig: {
        enableManualNodes: true,    // 手动节点前缀开关
        enableSubscriptions: true,  // 机场订阅前缀开关
        manualNodePrefix: '手动节点', // 手动节点前缀文本
    },
    NotifyThresholdDays: 3,
    NotifyThresholdPercent: 90,
    storageType: 'kv' // 新增：数据存储类型，默认 KV，可选 'd1'
};

const formatBytes = (bytes, decimals = 2) => {
    if (!+bytes || bytes < 0) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    // toFixed(dm) after dividing by pow(k, i) was producing large decimal numbers
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    if (i < 0) return '0 B'; // Handle log(0) case
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
};

// --- TG 通知函式 (无修改) ---
async function sendTgNotification(settings, message) {
    if (!settings.BotToken || !settings.ChatID) {
        return false;
    }

    // 为所有消息添加时间戳
    const now = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
    const fullMessage = `${message}\n\n*时间:* \`${now} (UTC+8)\``;

    const url = `https://api.telegram.org/bot${settings.BotToken}/sendMessage`;
    const payload = {
        chat_id: settings.ChatID,
        text: fullMessage,
        parse_mode: 'Markdown',
        disable_web_page_preview: true // 禁用链接预览，使消息更紧凑
    };

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (response.ok) {
            return true;
        } else {
            return false;
        }
    } catch (error) {
        return false;
    }
}

/**
 * 增强版TG通知，包含IP地理位置信息
 * @param {Object} settings - 设置对象
 * @param {string} type - 通知类型
 * @param {string} clientIp - 客户端IP
 * @param {string} additionalData - 额外数据
 * @returns {Promise<boolean>} - 是否发送成功
 */
async function sendEnhancedTgNotification(settings, type, clientIp, additionalData = '') {
    if (!settings.BotToken || !settings.ChatID) {
        return false;
    }

    let locationInfo = '';

    // 尝试获取IP地理位置信息
    try {
        const response = await fetch(`http://ip-api.com/json/${clientIp}?lang=zh-CN`, {
            cf: {
                // 设置较短的超时时间，避免影响主请求
                timeout: 3000
            }
        });

        if (response.ok) {
            const ipInfo = await response.json();
            if (ipInfo.status === 'success') {
                locationInfo = `
*国家:* \`${ipInfo.country || 'N/A'}\`
*城市:* \`${ipInfo.city || 'N/A'}\`
*ISP:* \`${ipInfo.org || 'N/A'}\`
*ASN:* \`${ipInfo.as || 'N/A'}\``;
            }
        }
    } catch (error) {
        // 获取IP位置信息失败，忽略错误
    }

    // 构建完整消息
    const now = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
    const message = `${type}

*IP 地址:* \`${clientIp}\`${locationInfo}

${additionalData}

*时间:* \`${now} (UTC+8)\``;

    const url = `https://api.telegram.org/bot${settings.BotToken}/sendMessage`;
    const payload = {
        chat_id: settings.ChatID,
        text: message,
        parse_mode: 'Markdown',
        disable_web_page_preview: true
    };

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (response.ok) {
            return true;
        } else {
            return false;
        }
    } catch (error) {
        return false;
    }
}

async function handleCronTrigger(env) {
    const storageAdapter = await getStorageAdapter(env);
    const originalSubs = await storageAdapter.get(KV_KEY_SUBS) || [];
    const allSubs = JSON.parse(JSON.stringify(originalSubs)); // 深拷贝以便比较
    const settings = await storageAdapter.get(KV_KEY_SETTINGS) || defaultSettings;

    const nodeRegex = /^(ss|ssr|vmess|vless|trojan|hysteria2?|hy|hy2|tuic|anytls|socks5):\/\//gm;
    let changesMade = false; // 修复: 声明changesMade变量

    for (const sub of allSubs) {
        if (sub.url.startsWith('http') && sub.enabled) {
            try {
                // --- 並行請求流量和節點內容 ---
                const trafficRequest = fetch(new Request(sub.url, {
                    headers: { 'User-Agent': 'Clash for Windows/0.20.39' },
                    redirect: "follow",
                    cf: { insecureSkipVerify: true }
                }));
                const nodeCountRequest = fetch(new Request(sub.url, {
                    headers: { 'User-Agent': 'MiSub-Cron-Updater/1.0' },
                    redirect: "follow",
                    cf: { insecureSkipVerify: true }
                }));
                const [trafficResult, nodeCountResult] = await Promise.allSettled([
                    Promise.race([trafficRequest, new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 8000))]),
                    Promise.race([nodeCountRequest, new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 8000))])
                ]);

                if (trafficResult.status === 'fulfilled' && trafficResult.value.ok) {
                    const userInfoHeader = trafficResult.value.headers.get('subscription-userinfo');
                    if (userInfoHeader) {
                        const info = {};
                        userInfoHeader.split(';').forEach(part => {
                            const [key, value] = part.trim().split('=');
                            if (key && value) info[key] = /^\d+$/.test(value) ? Number(value) : value;
                        });
                        sub.userInfo = info; // 更新流量資訊
                        await checkAndNotify(sub, settings, env); // 檢查並發送通知
                        changesMade = true;
                    }
                } else if (trafficResult.status === 'rejected') {
                    // 流量请求失败
                }

                if (nodeCountResult.status === 'fulfilled' && nodeCountResult.value.ok) {
                    const text = await nodeCountResult.value.text();
                    // 使用智能解码函数（支持伪装格式）
                    const decoded = smartDecodeSubscription(text);
                    const matches = decoded.match(nodeRegex);
                    if (matches) {
                        sub.nodeCount = matches.length; // 更新節點數量
                        changesMade = true;
                    }
                } else if (nodeCountResult.status === 'rejected') {
                    // 节点数量请求失败
                }

            } catch (e) {
                // 请求处理出错
            }
        }
    }

    if (changesMade) {
        await storageAdapter.put(KV_KEY_SUBS, allSubs);
    }
    return new Response("Cron job completed successfully.", { status: 200 });
}

// --- 认证与API处理的核心函数 (无修改) ---
async function createSignedToken(key, data) {
    if (!key || !data) throw new Error("Key and data are required for signing.");
    const encoder = new TextEncoder();
    const keyData = encoder.encode(key);
    const dataToSign = encoder.encode(data);
    const cryptoKey = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, dataToSign);
    return `${data}.${Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('')}`;
}
async function verifySignedToken(key, token) {
    if (!key || !token) return null;
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [data] = parts;
    const expectedToken = await createSignedToken(key, data);
    return token === expectedToken ? data : null;
}
async function authMiddleware(request, env) {
    if (!env.COOKIE_SECRET) return false;
    const cookie = request.headers.get('Cookie');
    const sessionCookie = cookie?.split(';').find(c => c.trim().startsWith(`${COOKIE_NAME}=`));
    if (!sessionCookie) return false;
    const token = sessionCookie.split('=')[1];
    const verifiedData = await verifySignedToken(env.COOKIE_SECRET, token);
    return verifiedData && (Date.now() - parseInt(verifiedData, 10) < SESSION_DURATION);
}

// sub: 要检查的订阅对象
// settings: 全局设置
// env: Cloudflare 环境
async function checkAndNotify(sub, settings, env) {
    if (!sub.userInfo) return; // 没有流量信息，无法检查

    const ONE_DAY_MS = 24 * 60 * 60 * 1000;
    const now = Date.now();

    // 1. 检查订阅到期
    if (sub.userInfo.expire) {
        const expiryDate = new Date(sub.userInfo.expire * 1000);
        const daysRemaining = Math.ceil((expiryDate - now) / ONE_DAY_MS);

        // 检查是否满足通知条件：剩余天数 <= 阈值
        if (daysRemaining <= (settings.NotifyThresholdDays || 7)) {
            // 检查上次通知时间，防止24小时内重复通知
            if (!sub.lastNotifiedExpire || (now - sub.lastNotifiedExpire > ONE_DAY_MS)) {
                const message = `🗓️ *订阅临期提醒* 🗓️

*订阅名称:* \`${sub.name || '未命名'}\`
*状态:* \`${daysRemaining < 0 ? '已过期' : `仅剩 ${daysRemaining} 天到期`}\`
*到期日期:* \`${expiryDate.toLocaleDateString('zh-CN')}\``;
                const sent = await sendTgNotification(settings, message);
                if (sent) {
                    sub.lastNotifiedExpire = now; // 更新通知时间戳
                }
            }
        }
    }

    // 2. 检查流量使用
    const { upload, download, total } = sub.userInfo;
    if (total > 0) {
        const used = upload + download;
        const usagePercent = Math.round((used / total) * 100);

        // 检查是否满足通知条件：已用百分比 >= 阈值
        if (usagePercent >= (settings.NotifyThresholdPercent || 90)) {
            // 检查上次通知时间，防止24小时内重复通知
            if (!sub.lastNotifiedTraffic || (now - sub.lastNotifiedTraffic > ONE_DAY_MS)) {
                const formatBytes = (bytes) => {
                    if (!+bytes) return '0 B';
                    const k = 1024;
                    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
                    const i = Math.floor(Math.log(bytes) / Math.log(k));
                    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
                };

                const message = `📈 *流量预警提醒* 📈

*订阅名称:* \`${sub.name || '未命名'}\`
*状态:* \`已使用 ${usagePercent}%\`
*详情:* \`${formatBytes(used)} / ${formatBytes(total)}\``;
                const sent = await sendTgNotification(settings, message);
                if (sent) {
                    sub.lastNotifiedTraffic = now; // 更新通知时间戳
                }
            }
        }
    }
}


// --- 主要 API 請求處理 ---
async function handleApiRequest(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/^\/api/, '');
    // [新增] 数据存储迁移接口 (KV -> D1)
    if (path === '/migrate_to_d1') {
        if (!await authMiddleware(request, env)) {
            return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
        }
        try {
            if (!env.MISUB_DB) {
                return new Response(JSON.stringify({
                    success: false,
                    message: 'D1 数据库未配置，请检查 wrangler.toml 配置'
                }), { status: 400 });
            }

            const migrationResult = await DataMigrator.migrateKVToD1(env);

            if (migrationResult.errors.length > 0) {
                return new Response(JSON.stringify({
                    success: false,
                    message: '迁移过程中出现错误',
                    details: migrationResult.errors,
                    partialSuccess: migrationResult
                }), { status: 500 });
            }

            return new Response(JSON.stringify({
                success: true,
                message: '数据已成功迁移到 D1 数据库',
                details: migrationResult
            }), { status: 200 });

        } catch (error) {
            console.error('[API Error /migrate_to_d1]', error);
            return new Response(JSON.stringify({
                success: false,
                message: `迁移失败: ${error.message}`
            }), { status: 500 });
        }
    }

    // [新增] 安全的、可重复执行的迁移接口
    if (path === '/migrate') {
        if (!await authMiddleware(request, env)) { return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 }); }
        try {
            const oldData = await env.MISUB_KV.get(OLD_KV_KEY, 'json');
            const newDataExists = await env.MISUB_KV.get(KV_KEY_SUBS) !== null;

            if (newDataExists) {
                return new Response(JSON.stringify({ success: true, message: '无需迁移，数据已是最新结构。' }), { status: 200 });
            }
            if (!oldData) {
                return new Response(JSON.stringify({ success: false, message: '未找到需要迁移的旧数据。' }), { status: 404 });
            }

            await env.MISUB_KV.put(KV_KEY_SUBS, JSON.stringify(oldData));
            await env.MISUB_KV.put(KV_KEY_PROFILES, JSON.stringify([]));
            await env.MISUB_KV.put(OLD_KV_KEY + '_migrated_on_' + new Date().toISOString(), JSON.stringify(oldData));
            await env.MISUB_KV.delete(OLD_KV_KEY);

            return new Response(JSON.stringify({ success: true, message: '数据迁移成功！' }), { status: 200 });
        } catch (e) {
            console.error('[API Error /migrate]', e);
            return new Response(JSON.stringify({ success: false, message: `迁移失败: ${e.message}` }), { status: 500 });
        }
    }

    if (path === '/login') {
        if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });
        try {
            const { password } = await request.json();
            if (password === env.ADMIN_PASSWORD) {
                const token = await createSignedToken(env.COOKIE_SECRET, String(Date.now()));
                const headers = new Headers({ 'Content-Type': 'application/json' });
                headers.append('Set-Cookie', `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_DURATION / 1000}`);
                return new Response(JSON.stringify({ success: true }), { headers });
            }
            return new Response(JSON.stringify({ error: '密码错误' }), { status: 401 });
        } catch (e) {
            console.error('[API Error /login]', e);
            return new Response(JSON.stringify({ error: '请求体解析失败' }), { status: 400 });
        }
    }
    if (!await authMiddleware(request, env)) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
    }

    switch (path) {
        case '/logout': {
            const headers = new Headers({ 'Content-Type': 'application/json' });
            headers.append('Set-Cookie', `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
            return new Response(JSON.stringify({ success: true }), { headers });
        }

        case '/data': {
            try {
                const storageAdapter = await getStorageAdapter(env);
                const [misubs, profiles, settings] = await Promise.all([
                    storageAdapter.get(KV_KEY_SUBS).then(res => res || []),
                    storageAdapter.get(KV_KEY_PROFILES).then(res => res || []),
                    storageAdapter.get(KV_KEY_SETTINGS).then(res => res || {})
                ]);
                const config = {
                    FileName: settings.FileName || 'MISUB',
                    mytoken: settings.mytoken || 'auto',
                    profileToken: settings.profileToken || 'profiles'
                };
                return new Response(JSON.stringify({ misubs, profiles, config }), { headers: { 'Content-Type': 'application/json' } });
            } catch (e) {
                console.error('[API Error /data]', 'Failed to read from storage:', e);
                return new Response(JSON.stringify({ error: '读取初始数据失败' }), { status: 500 });
            }
        }

        case '/misubs': {
            try {
                // 步骤1: 解析请求体
                let requestData;
                try {
                    requestData = await request.json();
                } catch (parseError) {
                    console.error('[API Error /misubs] JSON解析失败:', parseError);
                    return new Response(JSON.stringify({
                        success: false,
                        message: '请求数据格式错误，请检查数据格式'
                    }), { status: 400 });
                }

                const { misubs, profiles } = requestData;

                // 步骤2: 验证必需字段
                if (typeof misubs === 'undefined' || typeof profiles === 'undefined') {
                    return new Response(JSON.stringify({
                        success: false,
                        message: '请求体中缺少 misubs 或 profiles 字段'
                    }), { status: 400 });
                }

                // 步骤3: 验证数据类型
                if (!Array.isArray(misubs) || !Array.isArray(profiles)) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: 'misubs 和 profiles 必须是数组格式'
                    }), { status: 400 });
                }

                // 步骤4: 获取设置（带错误处理）
                let settings;
                try {
                    const storageAdapter = await getStorageAdapter(env);
                    settings = await storageAdapter.get(KV_KEY_SETTINGS) || defaultSettings;
                } catch (settingsError) {
                    settings = defaultSettings; // 使用默认设置继续
                }

                // 步骤5: 处理通知（非阻塞，错误不影响保存）
                try {
                    const notificationPromises = misubs
                        .filter(sub => sub && sub.url && sub.url.startsWith('http'))
                        .map(sub => checkAndNotify(sub, settings, env).catch(notifyError => {
                            // 通知失败不影响保存流程
                        }));

                    // 并行处理通知，但不等待完成
                    Promise.all(notificationPromises).catch(e => {
                        // 部分通知处理失败
                    });
                } catch (notificationError) {
                    // 通知系统错误，继续保存流程
                }

                // {{ AURA-X: Modify - 使用存储适配器保存数据. Approval: 寸止(ID:1735459200). }}
                // 步骤6: 保存数据到存储（使用存储适配器）
                try {
                    const storageAdapter = await getStorageAdapter(env);
                    await Promise.all([
                        storageAdapter.put(KV_KEY_SUBS, misubs),
                        storageAdapter.put(KV_KEY_PROFILES, profiles)
                    ]);
                } catch (storageError) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: `数据保存失败: ${storageError.message || '存储服务暂时不可用，请稍后重试'}`
                    }), { status: 500 });
                }

                return new Response(JSON.stringify({
                    success: true,
                    message: '订阅源及订阅组已保存'
                }));

            } catch (e) {
                return new Response(JSON.stringify({
                    success: false,
                    message: `保存失败: ${e.message || '服务器内部错误，请稍后重试'}`
                }), { status: 500 });
            }
        }

        case '/node_count': {
            if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });
            const { url: subUrl } = await request.json();
            if (!subUrl || typeof subUrl !== 'string' || !/^https?:\/\//.test(subUrl)) {
                return new Response(JSON.stringify({ error: 'Invalid or missing url' }), { status: 400 });
            }

            const result = { count: 0, userInfo: null };

            try {
                const fetchOptions = {
                    headers: { 'User-Agent': 'MiSub-Node-Counter/2.0' },
                    redirect: "follow",
                    cf: { insecureSkipVerify: true }
                };
                const trafficFetchOptions = {
                    headers: { 'User-Agent': 'Clash for Windows/0.20.39' },
                    redirect: "follow",
                    cf: { insecureSkipVerify: true }
                };

                const trafficRequest = fetch(new Request(subUrl, trafficFetchOptions));
                const nodeCountRequest = fetch(new Request(subUrl, fetchOptions));

                // --- [核心修正] 使用 Promise.allSettled 替换 Promise.all ---
                const responses = await Promise.allSettled([trafficRequest, nodeCountRequest]);

                // 1. 处理流量请求的结果
                if (responses[0].status === 'fulfilled' && responses[0].value.ok) {
                    const trafficResponse = responses[0].value;
                    const userInfoHeader = trafficResponse.headers.get('subscription-userinfo');
                    if (userInfoHeader) {
                        const info = {};
                        userInfoHeader.split(';').forEach(part => {
                            const [key, value] = part.trim().split('=');
                            if (key && value) info[key] = /^\d+$/.test(value) ? Number(value) : value;
                        });
                        result.userInfo = info;
                    }
                } else if (responses[0].status === 'rejected') {
                    // 流量请求失败
                }

                // 2. 处理节点数请求的结果
                if (responses[1].status === 'fulfilled' && responses[1].value.ok) {
                    const nodeCountResponse = responses[1].value;
                    const text = await nodeCountResponse.text();
                    // 使用智能解码函数（支持伪装格式）
                    const decoded = smartDecodeSubscription(text);
                    const lineMatches = decoded.match(/^(ss|ssr|vmess|vless|trojan|hysteria2?|hy|hy2|tuic|anytls|socks5):\/\//gm);
                    if (lineMatches) {
                        result.count = lineMatches.length;
                    }
                } else if (responses[1].status === 'rejected') {
                    // 节点数请求失败
                }

                // {{ AURA-X: Modify - 使用存储适配器优化节点计数更新. Approval: 寸止(ID:1735459200). }}
                // 只有在至少获取到一个有效信息时，才更新数据库
                if (result.userInfo || result.count > 0) {
                    const storageAdapter = await getStorageAdapter(env);
                    const originalSubs = await storageAdapter.get(KV_KEY_SUBS) || [];
                    const allSubs = JSON.parse(JSON.stringify(originalSubs)); // 深拷贝
                    const subToUpdate = allSubs.find(s => s.url === subUrl);

                    if (subToUpdate) {
                        subToUpdate.nodeCount = result.count;
                        subToUpdate.userInfo = result.userInfo;

                        await storageAdapter.put(KV_KEY_SUBS, allSubs);
                    }
                }

            } catch (e) {
                // 节点计数处理错误
            }

            return new Response(JSON.stringify(result), { headers: { 'Content-Type': 'application/json' } });
        }

        case '/fetch_external_url': { // New case
            if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });
            const { url: externalUrl } = await request.json();
            if (!externalUrl || typeof externalUrl !== 'string' || !/^https?:\/\//.test(externalUrl)) {
                return new Response(JSON.stringify({ error: 'Invalid or missing url' }), { status: 400 });
            }

            try {
                const response = await fetch(new Request(externalUrl, {
                    headers: { 'User-Agent': 'MiSub-Proxy/1.0' }, // Identify as proxy
                    redirect: "follow",
                    cf: { insecureSkipVerify: true } // Allow insecure SSL for flexibility
                }));

                if (!response.ok) {
                    return new Response(JSON.stringify({ error: `Failed to fetch external URL: ${response.status} ${response.statusText}` }), { status: response.status });
                }

                const content = await response.text();
                return new Response(content, { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });

            } catch (e) {
                return new Response(JSON.stringify({ error: `Failed to fetch external URL: ${e.message}` }), { status: 500 });
            }
        }

        // {{ AURA-X: Add - 批量节点更新API端点. Approval: 寸止(ID:1735459200). }}
        case '/batch_update_nodes': {
            if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });
            if (!await authMiddleware(request, env)) {
                return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
            }

            try {
                const { subscriptionIds } = await request.json();
                if (!Array.isArray(subscriptionIds)) {
                    return new Response(JSON.stringify({ error: 'subscriptionIds must be an array' }), { status: 400 });
                }

                const storageAdapter = await getStorageAdapter(env);
                const allSubs = await storageAdapter.get(KV_KEY_SUBS) || [];
                const subsToUpdate = allSubs.filter(sub => subscriptionIds.includes(sub.id) && sub.url.startsWith('http'));

                // 并行更新所有订阅的节点信息
                const updatePromises = subsToUpdate.map(async (sub) => {
                    try {
                        const fetchOptions = {
                            headers: { 'User-Agent': 'MiSub-Batch-Updater/1.0' },
                            redirect: "follow",
                            cf: { insecureSkipVerify: true }
                        };

                        const response = await Promise.race([
                            fetch(sub.url, fetchOptions),
                            new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 10000))
                        ]);

                        if (response.ok) {
                            // 更新流量信息
                            const userInfoHeader = response.headers.get('subscription-userinfo');
                            if (userInfoHeader) {
                                const info = {};
                                userInfoHeader.split(';').forEach(part => {
                                    const [key, value] = part.trim().split('=');
                                    if (key && value) info[key] = /^\d+$/.test(value) ? Number(value) : value;
                                });
                                sub.userInfo = info;
                            }

                            // 更新节点数量
                            const text = await response.text();
                            // 使用智能解码函数（支持伪装格式）
                            const decoded = smartDecodeSubscription(text);
                            const nodeRegex = /^(ss|ssr|vmess|vless|trojan|hysteria2?|hy|hy2|tuic|anytls|socks5):\/\//gm;
                            const matches = decoded.match(nodeRegex);
                            sub.nodeCount = matches ? matches.length : 0;

                            return { id: sub.id, success: true, nodeCount: sub.nodeCount };
                        } else {
                            return { id: sub.id, success: false, error: `HTTP ${response.status}` };
                        }
                    } catch (error) {
                        return { id: sub.id, success: false, error: error.message };
                    }
                });

                const results = await Promise.allSettled(updatePromises);
                const updateResults = results.map(result =>
                    result.status === 'fulfilled' ? result.value : { success: false, error: 'Promise rejected' }
                );

                // 使用存储适配器保存更新后的数据
                await storageAdapter.put(KV_KEY_SUBS, allSubs);

                return new Response(JSON.stringify({
                    success: true,
                    message: '批量更新完成',
                    results: updateResults
                }), { headers: { 'Content-Type': 'application/json' } });

            } catch (error) {
                return new Response(JSON.stringify({
                    success: false,
                    message: `批量更新失败: ${error.message}`
                }), { status: 500 });
            }
        }

        case '/debug_subscription': {
            if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });

            try {
                const { url: debugUrl, userAgent } = await request.json();
                if (!debugUrl || typeof debugUrl !== 'string' || !/^https?:\/\//.test(debugUrl)) {
                    return new Response(JSON.stringify({ error: 'Invalid or missing url' }), { status: 400 });
                }

                const result = {
                    url: debugUrl,
                    userAgent: userAgent || 'MiSub-Debug/1.0',
                    success: false,
                    rawContent: '',
                    processedContent: '',
                    validNodes: [],
                    ssNodes: [],
                    error: null
                };

                try {
                    const response = await fetch(new Request(debugUrl, {
                        headers: { 'User-Agent': result.userAgent },
                        redirect: "follow",
                        cf: { insecureSkipVerify: true }
                    }));

                    if (!response.ok) {
                        result.error = `HTTP ${response.status}: ${response.statusText}`;
                        return new Response(JSON.stringify(result), { headers: { 'Content-Type': 'application/json' } });
                    }

                    const text = await response.text();
                    result.rawContent = text.substring(0, 2000); // 限制原始内容长度

                    // 使用智能解码函数（支持伪装格式）
                    const processedText = smartDecodeSubscription(text);

                    result.processedContent = processedText.substring(0, 2000); // 限制处理后内容长度

                    // 提取所有有效节点
                    const allNodes = processedText.replace(/\r\n/g, '\n').split('\n')
                        .map(line => line.trim())
                        .filter(line => /^(ss|ssr|vmess|vless|trojan|hysteria2?|hy|hy2|tuic|anytls|socks5):\/\//.test(line));

                    result.validNodes = allNodes.slice(0, 20); // 限制显示节点数量

                    // 特别提取SS节点进行分析
                    result.ssNodes = allNodes.filter(line => line.startsWith('ss://')).map(line => {
                        try {
                            const hashIndex = line.indexOf('#');
                            let baseLink = hashIndex !== -1 ? line.substring(0, hashIndex) : line;
                            let fragment = hashIndex !== -1 ? line.substring(hashIndex) : '';

                            const protocolEnd = baseLink.indexOf('://');
                            const atIndex = baseLink.indexOf('@');
                            let analysis = {
                                original: line,
                                hasUrlEncoding: false,
                                fixed: line,
                                base64Part: '',
                                credentials: ''
                            };

                            if (protocolEnd !== -1 && atIndex !== -1) {
                                const base64Part = baseLink.substring(protocolEnd + 3, atIndex);
                                analysis.base64Part = base64Part;

                                if (base64Part.includes('%')) {
                                    analysis.hasUrlEncoding = true;
                                    const decodedBase64 = decodeURIComponent(base64Part);
                                    analysis.fixed = 'ss://' + decodedBase64 + baseLink.substring(atIndex) + fragment;

                                    try {
                                        analysis.credentials = atob(decodedBase64);
                                    } catch (e) {
                                        analysis.credentials = 'Base64解码失败: ' + e.message;
                                    }
                                } else {
                                    try {
                                        analysis.credentials = atob(base64Part);
                                    } catch (e) {
                                        analysis.credentials = 'Base64解码失败: ' + e.message;
                                    }
                                }
                            }

                            return analysis;
                        } catch (e) {
                            return {
                                original: line,
                                error: e.message
                            };
                        }
                    }).slice(0, 10); // 限制SS节点分析数量

                    result.success = true;
                    result.totalNodes = allNodes.length;
                    result.ssNodesCount = allNodes.filter(line => line.startsWith('ss://')).length;

                } catch (e) {
                    result.error = e.message;
                }

                return new Response(JSON.stringify(result), { headers: { 'Content-Type': 'application/json' } });

            } catch (e) {
                return new Response(JSON.stringify({ error: `调试失败: ${e.message}` }), { status: 500 });
            }
        }

        case '/get_nodes': {
            if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });

            try {
                const { url: subUrl } = await request.json();
                if (!subUrl || typeof subUrl !== 'string' || !/^https?:\/\//.test(subUrl)) {
                    return new Response(JSON.stringify({ error: 'Invalid or missing url' }), { status: 400 });
                }

                const fetchOptions = {
                    headers: { 'User-Agent': 'v2rayN/6.45' },
                    redirect: "follow",
                    cf: { insecureSkipVerify: true }
                };

                console.log(`[get_nodes] 使用 UA: ${smartUA} for ${subUrl}`);

                try {
                    const response = await Promise.race([
                        fetch(new Request(subUrl, fetchOptions)),
                        new Promise((_, reject) => setTimeout(() => reject(new Error('请求超时')), 10000))
                    ]);

                    if (!response.ok) {
                        return new Response(JSON.stringify({
                            error: `订阅请求失败: HTTP ${response.status}`,
                            nodes: []
                        }), { status: 200 });
                    }

                    let text = await response.text();

                    console.log('[get_nodes] 原始内容长度:', text.length);
                    console.log('[get_nodes] 原始内容前100字符:', text.substring(0, 100));

                    // 使用智能解码函数处理订阅内容（支持伪装格式和 Clash YAML）
                    const decodedText = smartDecodeSubscription(text);

                    console.log('[get_nodes] 解码后长度:', decodedText.length);
                    console.log('[get_nodes] 解码后前100字符:', decodedText.substring(0, 100));

                    // Singbox 配置暂不支持
                    if (decodedText.includes('outbounds') && decodedText.includes('inbounds') && decodedText.includes('route')) {
                        return new Response(JSON.stringify({
                            error: '该订阅返回的是 Singbox 完整配置文件，暂不支持解析。建议使用"直传模式"',
                            nodes: [],
                            hint: 'singbox_config'
                        }), { status: 200 });
                    }

                    // 提取节点
                    const validNodes = decodedText.replace(/\r\n/g, '\n').split('\n')
                        .map(line => line.trim())
                        .filter(line => /^(ss|ssr|vmess|vless|trojan|hysteria2?|hy|hy2|tuic|anytls|socks5):\/\//.test(line));

                    console.log('[get_nodes] 找到节点数量:', validNodes.length);

                    if (validNodes.length === 0) {
                        // 提供更详细的调试信息
                        const debugInfo = {
                            originalLength: text.length,
                            originalPreview: text.substring(0, 200),
                            decodedLength: decodedText.length,
                            decodedPreview: decodedText.substring(0, 500),
                            isBase64: isValidBase64(text.replace(/\s/g, ''))
                        };

                        return new Response(JSON.stringify({
                            error: '未找到任何有效节点。可能原因：1) 订阅链接已失效 2) 返回的是配置文件而非节点列表 3) 订阅格式不支持',
                            nodes: [],
                            debug: debugInfo
                        }), { status: 200 });
                    }

                    return new Response(JSON.stringify({
                        success: true,
                        nodes: validNodes,
                        count: validNodes.length
                    }), { headers: { 'Content-Type': 'application/json' } });

                } catch (fetchError) {
                    return new Response(JSON.stringify({
                        error: `获取订阅失败: ${fetchError.message}`,
                        nodes: []
                    }), { status: 200 });
                }

            } catch (e) {
                console.error('[API Error /get_nodes]', e);
                return new Response(JSON.stringify({
                    error: `处理失败: ${e.message}`,
                    nodes: []
                }), { status: 500 });
            }
        }

        case '/settings': {
            if (request.method === 'GET') {
                try {
                    const storageAdapter = await getStorageAdapter(env);
                    const settings = await storageAdapter.get(KV_KEY_SETTINGS) || {};
                    return new Response(JSON.stringify({ ...defaultSettings, ...settings }), { headers: { 'Content-Type': 'application/json' } });
                } catch (e) {
                    return new Response(JSON.stringify({ error: '读取设置失败' }), { status: 500 });
                }
            }
            if (request.method === 'POST') {
                try {
                    const newSettings = await request.json();
                    const storageAdapter = await getStorageAdapter(env);
                    const oldSettings = await storageAdapter.get(KV_KEY_SETTINGS) || {};
                    const finalSettings = { ...oldSettings, ...newSettings };

                    // 使用存储适配器保存设置
                    await storageAdapter.put(KV_KEY_SETTINGS, finalSettings);

                    const message = `⚙️ *MiSub 设置更新* ⚙️\n\n您的 MiSub 应用设置已成功更新。`;
                    await sendTgNotification(finalSettings, message);

                    return new Response(JSON.stringify({ success: true, message: '设置已保存' }));
                } catch (e) {
                    return new Response(JSON.stringify({ error: '保存设置失败' }), { status: 500 });
                }
            }
            return new Response('Method Not Allowed', { status: 405 });
        }
    }

    return new Response('API route not found', { status: 404 });
}
// --- 名称前缀辅助函数 (无修改) ---
function prependNodeName(link, prefix) {
    if (!prefix) return link;
    const appendToFragment = (baseLink, namePrefix) => {
        const hashIndex = baseLink.lastIndexOf('#');
        const originalName = hashIndex !== -1 ? decodeURIComponent(baseLink.substring(hashIndex + 1)) : '';
        const base = hashIndex !== -1 ? baseLink.substring(0, hashIndex) : baseLink;
        if (originalName.startsWith(namePrefix)) {
            return baseLink;
        }
        const newName = originalName ? `${namePrefix} - ${originalName}` : namePrefix;
        return `${base}#${encodeURIComponent(newName)}`;
    }
    if (link.startsWith('vmess://')) {
        try {
            const base64Part = link.substring('vmess://'.length);
            const binaryString = atob(base64Part);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            const jsonString = new TextDecoder('utf-8').decode(bytes);
            const nodeConfig = JSON.parse(jsonString);
            const originalPs = nodeConfig.ps || '';
            if (!originalPs.startsWith(prefix)) {
                nodeConfig.ps = originalPs ? `${prefix} - ${originalPs}` : prefix;
            }
            const newJsonString = JSON.stringify(nodeConfig);
            const newBase64Part = btoa(unescape(encodeURIComponent(newJsonString)));
            return 'vmess://' + newBase64Part;
        } catch (e) {
            console.error("为 vmess 节点添加名称前缀失败，将回退到通用方法。", e);
            return appendToFragment(link, prefix);
        }
    }
    return appendToFragment(link, prefix);
}

/**
 * 检测字符串是否为有效的Base64格式
 * @param {string} str - 要检测的字符串
 * @returns {boolean} - 是否为有效Base64
 */
function isValidBase64(str) {
    // 先移除所有空白字符(空格、换行、回车等)
    const cleanStr = str.replace(/\s/g, '');
    const base64Regex = /^[A-Za-z0-9+\/=]+$/;
    // 放宽长度限制，支持更短的内容
    return base64Regex.test(cleanStr) && cleanStr.length > 10;
}

/**
 * 智能解码订阅内容，支持伪装格式
 * @param {string} text - 原始内容
 * @returns {string} - 解码后的内容
 */
function smartDecodeSubscription(text) {
    if (!text) return '';

    const nodeRegex = /^(ss|ssr|vmess|vless|trojan|hysteria2?|hy|hy2|tuic|anytls|socks5):\/\//;

    // 1. 先尝试按行分割，检查是否已经是节点列表
    const lines = text.replace(/\r\n/g, '\n').split('\n');
    const hasNodes = lines.some(line => nodeRegex.test(line.trim()));

    if (hasNodes) {
        console.log('[smartDecode] 内容已经是节点列表');
        return text;
    }

    console.log('[smartDecode] 内容不是节点列表，尝试解码...');

    // 2. 检查是否为 Clash YAML 配置文件
    if (text.includes('proxies:') && (text.includes('port:') || text.includes('mode:'))) {
        console.log('[smartDecode] 检测到 Clash YAML 配置文件');
        try {
            const nodes = extractNodesFromClashYAML(text);
            if (nodes.length > 0) {
                console.log(`[smartDecode] 从 Clash 配置提取了 ${nodes.length} 个节点`);
                return nodes.join('\n');
            }
        } catch (e) {
            console.log('[smartDecode] Clash YAML 解析失败:', e.message);
        }
    }

    // 3. 尝试 Base64 解码
    try {
        const cleanedText = text.replace(/\s/g, '');
        const isBase64 = isValidBase64(cleanedText);

        console.log('[smartDecode] Base64 检查:', isBase64);
        console.log('[smartDecode] 清理后长度:', cleanedText.length);

        if (isBase64) {
            console.log('[smartDecode] 开始 Base64 解码...');

            const binaryString = atob(cleanedText);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            const decoded = new TextDecoder('utf-8', { fatal: false }).decode(bytes);

            console.log('[smartDecode] Base64 解码成功，长度:', decoded.length);
            console.log('[smartDecode] 解码后前100字符:', decoded.substring(0, 100));

            // 验证解码后的内容是否包含节点
            const decodedLines = decoded.replace(/\r\n/g, '\n').split('\n');
            const hasDecodedNodes = decodedLines.some(line => nodeRegex.test(line.trim()));

            console.log('[smartDecode] 解码后包含节点:', hasDecodedNodes);

            if (hasDecodedNodes) {
                return decoded;
            } else {
                console.log('[smartDecode] 解码后不包含有效节点，检查是否为 Clash 配置');
                // 解码后可能也是 Clash 配置
                if (decoded.includes('proxies:')) {
                    try {
                        const nodes = extractNodesFromClashYAML(decoded);
                        if (nodes.length > 0) {
                            console.log(`[smartDecode] 从 Base64 解码的 Clash 配置提取了 ${nodes.length} 个节点`);
                            return nodes.join('\n');
                        }
                    } catch (e) {
                        console.log('[smartDecode] Base64 解码后的 Clash YAML 解析失败:', e.message);
                    }
                }
            }
        }
    } catch (e) {
        console.log('[smartDecode] Base64 解码失败:', e.message);
    }

    // 4. 如果文本看起来像二进制数据，尝试直接作为 UTF-8 解析
    if (text.includes('\x00') || text.charCodeAt(0) > 127) {
        console.log('[smartDecode] 尝试二进制数据解析...');
        try {
            const encoder = new TextEncoder();
            const bytes = encoder.encode(text);
            const decoded = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
            const decodedLines = decoded.replace(/\r\n/g, '\n').split('\n');
            const hasDecodedNodes = decodedLines.some(line => nodeRegex.test(line.trim()));

            if (hasDecodedNodes) {
                console.log('[smartDecode] 二进制解析成功');
                return decoded;
            }
        } catch (e) {
            console.log('[smartDecode] 二进制解析失败:', e.message);
        }
    }

    // 5. 返回原始文本
    console.log('[smartDecode] 使用原始文本');
    return text;
}

/**
 * 根据客户端类型确定合适的用户代理
 * 参考CF-Workers-SUB的优雅策略：统一使用v2rayN UA获取订阅，简单而有效
 * @param {string} originalUserAgent - 原始用户代理字符串
 * @returns {string} - 处理后的用户代理字符串
 */
function getProcessedUserAgent(originalUserAgent, url = '') {
    if (!originalUserAgent) return originalUserAgent;

    // CF-Workers-SUB的精华策略：
    // 统一使用v2rayN UA获取订阅，绕过机场过滤同时保证获取完整节点
    // 不需要复杂的客户端判断，简单而有效
    return 'v2rayN/6.45';
}

// --- 节点列表生成函数 ---
async function generateCombinedNodeList(context, config, userAgent, misubs, prependedContent = '', profilePrefixSettings = null) {
    const nodeRegex = /^(ss|ssr|vmess|vless|trojan|hysteria2?|hy|hy2|tuic|anytls|socks5):\/\//g;

    // 判断是否启用手动节点前缀
    const shouldPrependManualNodes = profilePrefixSettings?.enableManualNodes ??
        config.prefixConfig?.enableManualNodes ??
        config.prependSubName ?? true;

    // 手动节点前缀文本
    const manualNodePrefix = profilePrefixSettings?.manualNodePrefix ??
        config.prefixConfig?.manualNodePrefix ??
        '手动节点';

    const processedManualNodes = misubs.filter(sub => !sub.url.toLowerCase().startsWith('http')).map(node => {
        if (node.isExpiredNode) {
            return node.url; // Directly use the URL for expired node
        } else {
            // 修复手动SS节点中的URL编码问题
            let processedUrl = node.url;
            if (processedUrl.startsWith('ss://')) {
                try {
                    const hashIndex = processedUrl.indexOf('#');
                    let baseLink = hashIndex !== -1 ? processedUrl.substring(0, hashIndex) : processedUrl;
                    let fragment = hashIndex !== -1 ? processedUrl.substring(hashIndex) : '';

                    // 检查base64部分是否包含URL编码字符
                    const protocolEnd = baseLink.indexOf('://');
                    const atIndex = baseLink.indexOf('@');
                    if (protocolEnd !== -1 && atIndex !== -1) {
                        const base64Part = baseLink.substring(protocolEnd + 3, atIndex);
                        if (base64Part.includes('%')) {
                            // 解码URL编码的base64部分
                            const decodedBase64 = decodeURIComponent(base64Part);
                            baseLink = 'ss://' + decodedBase64 + baseLink.substring(atIndex);
                        }
                    }
                    processedUrl = baseLink + fragment;
                } catch (e) {
                    // 如果处理失败，使用原始链接
                }
            }

            return shouldPrependManualNodes ? prependNodeName(processedUrl, manualNodePrefix) : processedUrl;
        }
    }).join('\n');

    const httpSubs = misubs.filter(sub => sub.url.toLowerCase().startsWith('http'));

    // 用于跟踪每个订阅的解析结果
    const subscriptionResults = [];

    const subPromises = httpSubs.map(async (sub) => {
        try {
            // 使用处理后的用户代理
            const processedUserAgent = getProcessedUserAgent(userAgent, sub.url);
            const requestHeaders = {
                'User-Agent': processedUserAgent,
                'Accept': '*/*',
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache'
            };

            console.log(`[generateCombinedNodeList] 正在请求: ${sub.url}`);
            console.log(`[generateCombinedNodeList] 使用 UA: ${processedUserAgent}`);

            const response = await Promise.race([
                fetch(new Request(sub.url, {
                    headers: requestHeaders,
                    redirect: "follow",
                    cf: {
                        cacheTtl: 0,
                        cacheEverything: false
                    }
                })),
                new Promise((_, reject) => setTimeout(() => reject(new Error('Request timed out')), 10000))
            ]);

            console.log(`[generateCombinedNodeList] 响应状态: ${response.status} ${response.statusText}`);
            console.log(`[generateCombinedNodeList] Content-Type: ${response.headers.get('content-type')}`);

            if (!response.ok) {
                console.error(`[generateCombinedNodeList] 订阅请求失败: ${sub.url}, 状态: ${response.status}`);
                console.error(`[generateCombinedNodeList] 响应头:`, [...response.headers.entries()]);
                return '';
            }
            let text = await response.text();

            // 使用智能解码函数（支持伪装格式如 .iso, .jpg 等）
            // smartDecodeSubscription 会自动处理 Clash YAML，将其转换为节点列表
            text = smartDecodeSubscription(text);

            // 检测是否为 Singbox 配置文件（Clash 已在 smartDecodeSubscription 中处理）
            if (text.includes('outbounds') && text.includes('inbounds') && text.includes('route')) {
                // 这是完整的Singbox配置文件，不是节点列表
                console.log('[generateCombinedNodeList] 检测到 Singbox 完整配置，跳过');
                return '';
            }
            let validNodes = text.replace(/\r\n/g, '\n').split('\n')
                .map(line => line.trim())
                .filter(line => /^(ss|ssr|vmess|vless|trojan|hysteria2?|hy|hy2|tuic|anytls|socks5):\/\//.test(line))
                .map(line => {
                    // 修复SS节点中的URL编码问题
                    if (line.startsWith('ss://') || line.startsWith('vless://') || line.startsWith('trojan://')) {
                        try {
                            const hashIndex = line.indexOf('#');
                            let baseLink = hashIndex !== -1 ? line.substring(0, hashIndex) : line;
                            let fragment = hashIndex !== -1 ? line.substring(hashIndex) : '';

                            // 检查base64部分是否包含URL编码字符
                            const protocolEnd = baseLink.indexOf('://');
                            const atIndex = baseLink.indexOf('@');
                            if (protocolEnd !== -1 && atIndex !== -1) {
                                const base64Part = baseLink.substring(protocolEnd + 3, atIndex);
                                if (base64Part.includes('%')) {
                                    // 解码URL编码的base64部分
                                    const decodedBase64 = decodeURIComponent(base64Part);
                                    const protocol = baseLink.substring(0, protocolEnd);
                                    baseLink = protocol + '://' + decodedBase64 + baseLink.substring(atIndex);
                                }
                            }
                            return baseLink + fragment;
                        } catch (e) {
                            // 如果处理失败，返回原始链接
                            return line;
                        }
                    }
                    return line;
                });

            // [核心重構] 引入白名單 (keep:) 和黑名單 (exclude) 模式
            if (sub.exclude && sub.exclude.trim() !== '') {
                const rules = sub.exclude.trim().split('\n').map(r => r.trim()).filter(Boolean);

                const keepRules = rules.filter(r => r.toLowerCase().startsWith('keep:'));

                if (keepRules.length > 0) {
                    // --- 白名單模式 (Inclusion Mode) ---
                    const nameRegexParts = [];
                    const protocolsToKeep = new Set();

                    keepRules.forEach(rule => {
                        const content = rule.substring('keep:'.length).trim();
                        if (content.toLowerCase().startsWith('proto:')) {
                            const protocols = content.substring('proto:'.length).split(',').map(p => p.trim().toLowerCase());
                            protocols.forEach(p => protocolsToKeep.add(p));
                        } else {
                            nameRegexParts.push(content);
                        }
                    });

                    const nameRegex = nameRegexParts.length > 0 ? new RegExp(nameRegexParts.join('|'), 'i') : null;

                    validNodes = validNodes.filter(nodeLink => {
                        // 檢查協議是否匹配
                        const protocolMatch = nodeLink.match(/^(.*?):\/\//);
                        const protocol = protocolMatch ? protocolMatch[1].toLowerCase() : '';
                        if (protocolsToKeep.has(protocol)) {
                            return true;
                        }

                        // 檢查名稱是否匹配
                        if (nameRegex) {
                            const hashIndex = nodeLink.lastIndexOf('#');
                            if (hashIndex !== -1) {
                                try {
                                    const nodeName = decodeURIComponent(nodeLink.substring(hashIndex + 1));
                                    if (nameRegex.test(nodeName)) {
                                        return true;
                                    }
                                } catch (e) { /* 忽略解碼錯誤 */ }
                            }
                        }
                        return false; // 白名單模式下，不匹配任何規則則排除
                    });

                } else {
                    // --- 黑名單模式 (Exclusion Mode) ---
                    const protocolsToExclude = new Set();
                    const nameRegexParts = [];

                    rules.forEach(rule => {
                        if (rule.toLowerCase().startsWith('proto:')) {
                            const protocols = rule.substring('proto:'.length).split(',').map(p => p.trim().toLowerCase());
                            protocols.forEach(p => protocolsToExclude.add(p));
                        } else {
                            nameRegexParts.push(rule);
                        }
                    });

                    const nameRegex = nameRegexParts.length > 0 ? new RegExp(nameRegexParts.join('|'), 'i') : null;

                    validNodes = validNodes.filter(nodeLink => {
                        const protocolMatch = nodeLink.match(/^(.*?):\/\//);
                        const protocol = protocolMatch ? protocolMatch[1].toLowerCase() : '';
                        if (protocolsToExclude.has(protocol)) {
                            return false;
                        }

                        if (nameRegex) {
                            const hashIndex = nodeLink.lastIndexOf('#');
                            if (hashIndex !== -1) {
                                try {
                                    const nodeName = decodeURIComponent(nodeLink.substring(hashIndex + 1));
                                    if (nameRegex.test(nodeName)) {
                                        return false;
                                    }
                                } catch (e) { /* 忽略解碼錯誤 */ }
                            }
                            // 修复：对于vmess协议，需要特殊处理节点名称
                            else if (protocol === 'vmess') {
                                try {
                                    // 提取vmess链接中的Base64部分
                                    const base64Part = nodeLink.substring('vmess://'.length);
                                    // 解码Base64
                                    const binaryString = atob(base64Part);
                                    const bytes = new Uint8Array(binaryString.length);
                                    for (let i = 0; i < binaryString.length; i++) {
                                        bytes[i] = binaryString.charCodeAt(i);
                                    }
                                    const jsonString = new TextDecoder('utf-8').decode(bytes);
                                    const nodeConfig = JSON.parse(jsonString);
                                    const nodeName = nodeConfig.ps || '';
                                    if (nameRegex.test(nodeName)) {
                                        return false;
                                    }
                                } catch (e) { /* 忽略解码错误 */ }
                            }
                        }
                        return true;
                    });
                }
            }

            // 判断是否启用订阅前缀
            const shouldPrependSubscriptions = profilePrefixSettings?.enableSubscriptions ??
                config.prefixConfig?.enableSubscriptions ??
                config.prependSubName ?? true;

            // 记录解析结果
            const hasNodes = validNodes.length > 0;
            subscriptionResults.push({
                url: sub.url,
                name: sub.name,
                success: hasNodes,
                nodeCount: validNodes.length
            });

            return (shouldPrependSubscriptions && sub.name)
                ? validNodes.map(node => prependNodeName(node, sub.name)).join('\n')
                : validNodes.join('\n');
        } catch (e) {
            // 订阅处理错误
            console.error(`[generateCombinedNodeList] 订阅处理失败: ${sub.url}`, e.message);
            subscriptionResults.push({
                url: sub.url,
                name: sub.name,
                success: false,
                nodeCount: 0,
                error: e.message
            });
            // 返回空字符串，让 subconverter 直接处理原始 URL
            return '';
        }
    });
    const processedSubContents = await Promise.all(subPromises);
    const combinedContent = (processedManualNodes + '\n' + processedSubContents.join('\n'));
    const uniqueNodesString = [...new Set(combinedContent.split('\n').map(line => line.trim()).filter(line => line))].join('\n');

    // 确保最终的字符串在非空时以换行符结束，以兼容 subconverter
    let finalNodeList = uniqueNodesString;
    if (finalNodeList.length > 0 && !finalNodeList.endsWith('\n')) {
        finalNodeList += '\n';
    }

    // 将虚假节点（如果存在）插入到列表最前面
    if (prependedContent) {
        finalNodeList = `${prependedContent}\n${finalNodeList}`;
    }

    // 返回节点列表和解析结果
    return {
        nodeList: finalNodeList,
        subscriptionResults: subscriptionResults
    };
}

// --- [核心修改] 订阅处理函数 ---
async function handleMisubRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const userAgentHeader = request.headers.get('User-Agent') || "Unknown";

    const storageAdapter = await getStorageAdapter(env);
    const [settingsData, misubsData, profilesData] = await Promise.all([
        storageAdapter.get(KV_KEY_SETTINGS),
        storageAdapter.get(KV_KEY_SUBS),
        storageAdapter.get(KV_KEY_PROFILES)
    ]);
    const settings = settingsData || {};
    const allMisubs = misubsData || [];
    const allProfiles = profilesData || [];
    // 关键：我们在这里定义了 `config`，后续都应该使用它
    const config = migrateConfigSettings({ ...defaultSettings, ...settings });

    let token = '';
    let profileIdentifier = null;
    const pathSegments = url.pathname.replace(/^\/sub\//, '/').split('/').filter(Boolean);

    if (pathSegments.length > 0) {
        token = pathSegments[0];
        if (pathSegments.length > 1) {
            profileIdentifier = pathSegments[1];
        }
    } else {
        token = url.searchParams.get('token');
    }

    let targetMisubs;
    let subName = config.FileName;
    let effectiveSubConverter;
    let effectiveSubConfig;
    let isProfileExpired = false; // Moved declaration here

    const DEFAULT_EXPIRED_NODE = `trojan://00000000-0000-0000-0000-000000000000@127.0.0.1:443#${encodeURIComponent('您的订阅已失效')}`;

    if (profileIdentifier) {

        // [修正] 使用 config 變量
        if (!token || token !== config.profileToken) {
            return new Response('Invalid Profile Token', { status: 403 });
        }
        const profile = allProfiles.find(p => (p.customId && p.customId === profileIdentifier) || p.id === profileIdentifier);
        if (profile && profile.enabled) {
            // Check if the profile has an expiration date and if it's expired

            if (profile.expiresAt) {
                const expiryDate = new Date(profile.expiresAt);
                const now = new Date();
                if (now > expiryDate) {
                    isProfileExpired = true;
                }
            }

            if (isProfileExpired) {
                subName = profile.name; // Still use profile name for filename
                targetMisubs = [{ id: 'expired-node', url: DEFAULT_EXPIRED_NODE, name: '您的订阅已到期', isExpiredNode: true }]; // Set expired node as the only targetMisub
            } else {
                subName = profile.name;
                const profileSubIds = new Set(profile.subscriptions);
                const profileNodeIds = new Set(profile.manualNodes);
                targetMisubs = allMisubs.filter(item => {
                    const isSubscription = item.url.startsWith('http');
                    const isManualNode = !isSubscription;

                    // Check if the item belongs to the current profile and is enabled
                    const belongsToProfile = (isSubscription && profileSubIds.has(item.id)) || (isManualNode && profileNodeIds.has(item.id));
                    if (!item.enabled || !belongsToProfile) {
                        return false;
                    }
                    return true;
                });
            }
            effectiveSubConverter = profile.subConverter && profile.subConverter.trim() !== '' ? profile.subConverter : config.subConverter;
            effectiveSubConfig = profile.subConfig && profile.subConfig.trim() !== '' ? profile.subConfig : config.subConfig;
        } else {
            return new Response('Profile not found or disabled', { status: 404 });
        }
    } else {
        // [修正] 使用 config 變量
        if (!token || token !== config.mytoken) {
            return new Response('Invalid Token', { status: 403 });
        }
        targetMisubs = allMisubs.filter(s => s.enabled);
        // [修正] 使用 config 變量
        effectiveSubConverter = config.subConverter;
        effectiveSubConfig = config.subConfig;
    }

    if (!effectiveSubConverter || effectiveSubConverter.trim() === '') {
        return new Response('Subconverter backend is not configured.', { status: 500 });
    }

    let targetFormat = url.searchParams.get('target');
    if (!targetFormat) {
        const supportedFormats = ['clash', 'singbox', 'surge', 'loon', 'base64', 'v2ray', 'trojan'];
        for (const format of supportedFormats) {
            if (url.searchParams.has(format)) {
                if (format === 'v2ray' || format === 'trojan') { targetFormat = 'base64'; } else { targetFormat = format; }
                break;
            }
        }
    }
    if (!targetFormat) {
        const ua = userAgentHeader.toLowerCase();
        // 使用陣列來保證比對的優先順序
        const uaMapping = [
            // Mihomo/Meta 核心的客戶端 - 需要clash格式
            ['flyclash', 'clash'],
            ['mihomo', 'clash'],
            ['clash.meta', 'clash'],
            ['clash-verge', 'clash'],
            ['meta', 'clash'],

            // 其他客戶端
            ['stash', 'clash'],
            ['nekoray', 'clash'],
            ['sing-box', 'singbox'],
            ['shadowrocket', 'base64'],
            ['v2rayn', 'base64'],
            ['v2rayng', 'base64'],
            ['surge', 'surge'],
            ['loon', 'loon'],
            ['quantumult%20x', 'quanx'],
            ['quantumult', 'quanx'],

            // 最後才匹配通用的 clash，作為向下相容
            ['clash', 'clash']
        ];

        for (const [keyword, format] of uaMapping) {
            if (ua.includes(keyword)) {
                targetFormat = format;
                break; // 找到第一個符合的就停止
            }
        }
    }
    if (!targetFormat) { targetFormat = 'base64'; }

    if (!url.searchParams.has('callback_token')) {
        const clientIp = request.headers.get('CF-Connecting-IP') || 'N/A';
        const country = request.headers.get('CF-IPCountry') || 'N/A';
        const domain = url.hostname;

        let additionalData = `*域名:* \`${domain}\`\n*客户端:* \`${userAgentHeader}\`\n*请求格式:* \`${targetFormat}\``;

        if (profileIdentifier) {
            additionalData += `\n*订阅组:* \`${subName}\``;
            const profile = allProfiles.find(p => (p.customId && p.customId === profileIdentifier) || p.id === profileIdentifier);
            if (profile && profile.expiresAt) {
                const expiryDateStr = new Date(profile.expiresAt).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
                additionalData += `\n*到期时间:* \`${expiryDateStr}\``;
            }
        }

        // 使用增强版TG通知，包含IP地理位置信息
        context.waitUntil(sendEnhancedTgNotification(config, '🛰️ *订阅被访问*', clientIp, additionalData));
    }

    let prependedContentForSubconverter = '';

    if (isProfileExpired) { // Use the flag set earlier
        prependedContentForSubconverter = ''; // Expired node is now in targetMisubs
    } else {
        // Otherwise, add traffic remaining info if applicable
        const totalRemainingBytes = targetMisubs.reduce((acc, sub) => {
            if (sub.enabled && sub.userInfo && sub.userInfo.total > 0) {
                const used = (sub.userInfo.upload || 0) + (sub.userInfo.download || 0);
                const remaining = sub.userInfo.total - used;
                return acc + Math.max(0, remaining);
            }
            return acc;
        }, 0);
        if (totalRemainingBytes > 0) {
            const formattedTraffic = formatBytes(totalRemainingBytes);
            const fakeNodeName = `流量剩余 ≫ ${formattedTraffic}`;
            prependedContentForSubconverter = `trojan://00000000-0000-0000-0000-000000000000@127.0.0.1:443#${encodeURIComponent(fakeNodeName)}`;
        }
    }

    const { nodeList: combinedNodeList, subscriptionResults } = await generateCombinedNodeList(
        context,
        config,
        userAgentHeader,
        targetMisubs,
        prependedContentForSubconverter,
        profileIdentifier ? allProfiles.find(p => (p.customId && p.customId === profileIdentifier) || p.id === profileIdentifier)?.prefixSettings : null
    );

    if (targetFormat === 'base64') {
        let contentToEncode;
        if (isProfileExpired) {
            contentToEncode = DEFAULT_EXPIRED_NODE + '\n'; // Return the expired node link for base64 clients
        } else {
            contentToEncode = combinedNodeList;
        }
        const headers = { "Content-Type": "text/plain; charset=utf-8", 'Cache-Control': 'no-store, no-cache' };
        return new Response(btoa(unescape(encodeURIComponent(contentToEncode))), { headers });
    }

    const base64Content = btoa(unescape(encodeURIComponent(combinedNodeList)));

    const callbackToken = await getCallbackToken(env);
    const callbackPath = profileIdentifier ? `/${token}/${profileIdentifier}` : `/${token}`;
    const callbackUrl = `${url.protocol}//${url.host}${callbackPath}?target=base64&callback_token=${callbackToken}`;
    if (url.searchParams.get('callback_token') === callbackToken) {
        const headers = { "Content-Type": "text/plain; charset=utf-8", 'Cache-Control': 'no-store, no-cache' };
        return new Response(base64Content, { headers });
    }

    const subconverterUrl = new URL(`https://${effectiveSubConverter}/sub`);
    subconverterUrl.searchParams.set('target', targetFormat);

    // 根据解析结果构建 URL 源列表
    const urlSources = [];

    // 如果本地成功解析了节点，添加 callback（包含已重命名的节点）
    const hasLocalNodes = combinedNodeList.trim().length > 0;
    if (hasLocalNodes) {
        urlSources.push(callbackUrl);
        console.log('[handleMisubRequest] 添加本地解析的节点 (callback)');
    }

    // 对于解析失败的订阅，直接添加原始 URL 让 subconverter 处理
    subscriptionResults.forEach(result => {
        if (!result.success && result.url) {
            urlSources.push(result.url);
            console.log(`[handleMisubRequest] 添加失败订阅的原始 URL: ${result.url}`);
        }
    });

    // 如果没有任何源，至少添加 callback
    if (urlSources.length === 0) {
        urlSources.push(callbackUrl);
        console.log('[handleMisubRequest] 没有任何源，使用 callback 兜底');
    }

    subconverterUrl.searchParams.set('url', urlSources.join('|'));
    if ((targetFormat === 'clash' || targetFormat === 'loon' || targetFormat === 'surge') && effectiveSubConfig && effectiveSubConfig.trim() !== '') {
        subconverterUrl.searchParams.set('config', effectiveSubConfig);
    }
    subconverterUrl.searchParams.set('new_name', 'true');

    try {
        const subconverterResponse = await fetch(subconverterUrl.toString(), {
            method: 'GET',
            headers: { 'User-Agent': 'Mozilla/5.0' },
        });
        if (!subconverterResponse.ok) {
            const errorBody = await subconverterResponse.text();
            throw new Error(`Subconverter service returned status: ${subconverterResponse.status}. Body: ${errorBody}`);
        }
        const responseText = await subconverterResponse.text();

        const responseHeaders = new Headers(subconverterResponse.headers);
        responseHeaders.set("Content-Disposition", `attachment; filename*=utf-8''${encodeURIComponent(subName)}`);
        responseHeaders.set('Content-Type', 'text/plain; charset=utf-8');
        responseHeaders.set('Cache-Control', 'no-store, no-cache');
        return new Response(responseText, { status: subconverterResponse.status, statusText: subconverterResponse.statusText, headers: responseHeaders });
    } catch (error) {
        console.error(`[MiSub Final Error] ${error.message}`);
        return new Response(`Error connecting to subconverter: ${error.message}`, { status: 502 });
    }
}

async function getCallbackToken(env) {
    const secret = env.COOKIE_SECRET || 'default-callback-secret';
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secret);
    const cryptoKey = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode('callback-static-data'));
    return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
}


// --- [核心修改] Cloudflare Pages Functions 主入口 ---
export async function onRequest(context) {
    const { request, env, next } = context;
    const url = new URL(request.url);

    // **核心修改：判斷是否為定時觸發**
    if (request.headers.get("cf-cron")) {
        return handleCronTrigger(env);
    }

    if (url.pathname.startsWith('/api/')) {
        const response = await handleApiRequest(request, env);
        return response;
    }
    const isStaticAsset = /^\/(assets|@vite|src)\/./.test(url.pathname) || /\.\w+$/.test(url.pathname);
    if (!isStaticAsset && url.pathname !== '/') {
        return handleMisubRequest(context);
    }
    return next();
}