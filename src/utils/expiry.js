/**
 * 有效期工具：统一「默认一年 / 是否过期 / date 输入框」格式，避免各处手写日期差一天。
 */

/** 临期红字阈值（天）：剩余天数 ≤ 此值时用红色强调 */
export const EXPIRY_WARN_DAYS = 30;

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
 * 计算距到期还剩几天（按本地日零点对齐，与机场订阅卡片一致）。
 * @param {string|null|undefined} expiresAt
 * @param {Date} [now]
 * @returns {number|null} 无有效期返回 null；已过期为负数
 */
export function getDaysRemaining(expiresAt, now = new Date()) {
    if (!expiresAt) return null;
    const expiryDate = new Date(expiresAt);
    if (Number.isNaN(expiryDate.getTime())) return null;
    const dayExpiry = new Date(expiryDate);
    dayExpiry.setHours(0, 0, 0, 0);
    const dayNow = new Date(now);
    dayNow.setHours(0, 0, 0, 0);
    return Math.ceil((dayExpiry - dayNow) / (1000 * 60 * 60 * 24));
}

/**
 * 临期/过期用红色，其余用灰色（供列表徽章 class 使用）。
 * @param {number|null} daysRemaining
 * @returns {string}
 */
export function getExpiryStyleClass(daysRemaining) {
    if (daysRemaining === null || daysRemaining === undefined) return '';
    if (daysRemaining < 0 || daysRemaining <= EXPIRY_WARN_DAYS) {
        return 'text-red-500 font-semibold';
    }
    return 'text-gray-500 dark:text-gray-400';
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
 * 把 expiresAt 转成 `<input type="date">` 可用的 YYYY-MM-DD（本地时区）。
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
 * 新建表单默认的 date input 值（今天 + 1 年的 YYYY-MM-DD）。
 * @param {Date} [from]
 * @returns {string}
 */
export function defaultExpiresAtDateInput(from = new Date()) {
    return toDateInputValue(defaultExpiresAtOneYear(from));
}

/**
 * 将 date input 的 YYYY-MM-DD 转为当天结束时刻的 ISO，与订阅组保存习惯对齐。
 * @param {string|null|undefined} dateInput
 * @returns {string}
 */
export function dateInputToExpiresAt(dateInput) {
    if (!dateInput) return '';
    const date = new Date(dateInput);
    if (Number.isNaN(date.getTime())) return '';
    date.setHours(23, 59, 59, 999);
    return date.toISOString();
}
