/**
 * 有效期工具：与前端 src/utils/expiry.js 保持同语义，供 Worker 拉取链路过滤/写回。
 */

/**
 * 判断 expiresAt 是否已过期；空值或非法日期视为永不过期（兼容旧数据）。
 * @param {string|null|undefined} expiresAt
 * @param {Date} [now]
 * @returns {boolean}
 */
export function isExpired(expiresAt, now = new Date()) {
    if (!expiresAt) return false;
    const date = new Date(expiresAt);
    if (Number.isNaN(date.getTime())) return false;
    return now > date;
}

/**
 * 生成一年后当天结束时刻的 ISO 字符串，作为新建项默认有效期。
 * @param {Date} [from]
 * @returns {string}
 */
export function defaultExpiresAtOneYear(from = new Date()) {
    const date = new Date(from);
    date.setFullYear(date.getFullYear() + 1);
    date.setHours(23, 59, 59, 999);
    return date.toISOString();
}

/**
 * 把 expiresAt 转成 YYYY-MM-DD（本地时区），供需要 date 字符串的调用方使用。
 * @param {string|null|undefined} expiresAt
 * @returns {string}
 */
export function toDateInputValue(expiresAt) {
    if (!expiresAt) return '';
    const date = new Date(expiresAt);
    if (Number.isNaN(date.getTime())) return '';
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
}

/**
 * 判断条目是否为手动节点（非 http(s) URL）。
 * @param {{ url?: string }|null|undefined} item
 * @returns {boolean}
 */
export function isManualNodeUrl(item) {
    return typeof item?.url === 'string' && item.url.length > 0 && !/^https?:\/\//i.test(item.url.trim());
}

/**
 * 条目是否因有效期失效而不应进入订阅输出。
 * @param {{ url?: string, expiresAt?: string, enabled?: boolean }|null|undefined} item
 * @param {Date} [now]
 * @returns {boolean}
 */
export function shouldSkipExpiredManualNode(item, now = new Date()) {
    return isManualNodeUrl(item) && isExpired(item?.expiresAt, now);
}

/**
 * 将仍启用但已过期的手动节点/订阅组标记为 disabled，并写回存储。
 * 在拉取路径用 waitUntil 调用，避免阻塞响应。
 * @param {object} storageAdapter
 * @param {{ subscriptionIds?: string[], profileIds?: string[] }} targets
 */
export async function persistExpiryDisables(storageAdapter, { subscriptionIds = [], profileIds = [] } = {}) {
    const uniqueSubIds = [...new Set(subscriptionIds.filter(Boolean))];
    const uniqueProfileIds = [...new Set(profileIds.filter(Boolean))];

    if (uniqueSubIds.length > 0 && typeof storageAdapter.getAllSubscriptions === 'function') {
        const all = await storageAdapter.getAllSubscriptions();
        let changed = false;
        const idSet = new Set(uniqueSubIds);
        const next = all.map((item) => {
            if (!idSet.has(item.id) || item.enabled === false) return item;
            changed = true;
            return { ...item, enabled: false };
        });
        if (changed) {
            if (typeof storageAdapter.putAllSubscriptions === 'function') {
                await storageAdapter.putAllSubscriptions(next);
            } else {
                await storageAdapter.put('misub_subscriptions_v1', next);
            }
        }
    }

    if (uniqueProfileIds.length > 0 && typeof storageAdapter.getAllProfiles === 'function') {
        const all = await storageAdapter.getAllProfiles();
        let changed = false;
        const idSet = new Set(uniqueProfileIds);
        const next = all.map((item) => {
            if (!idSet.has(item.id) || item.enabled === false) return item;
            changed = true;
            return { ...item, enabled: false };
        });
        if (changed) {
            if (typeof storageAdapter.putAllProfiles === 'function') {
                await storageAdapter.putAllProfiles(next);
            } else {
                await storageAdapter.put('misub_profiles_v1', next);
            }
        }
    }
}
