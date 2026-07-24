/**
 * 通知服务 (核心实现)
 * 支持 Telegram Bot 与企业微信群机器人 Webhook。
 * @author MiSub Team
 */

/**
 * 转义 Telegram HTML 模式下的特殊字符
 * @param {string} text - 待转义的文本
 * @returns {string} - 转义后的文本
 */
export function tgEscape(text) {
    if (typeof text !== 'string') return String(text || '');
    return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/**
 * 将通知里常用的 HTML 片段转为企微可读纯文本。
 * @param {string} html
 * @returns {string}
 */
export function htmlToPlainText(html) {
    return String(html || '')
        .replace(/<br\s*\/?>/gi, '\n')
        .replace(/<\/p>/gi, '\n')
        .replace(/<\/?(b|strong|i|em|code)>/gi, '')
        .replace(/<a\b[^>]*>(.*?)<\/a>/gi, '$1')
        .replace(/<[^>]+>/g, '')
        .replace(/&amp;/g, '&')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&nbsp;/g, ' ')
        .trim();
}

function isValidWeComWebhook(url) {
    return /^https:\/\/qyapi\.weixin\.qq\.com\/cgi-bin\/webhook\/send\?key=[A-Za-z0-9_-]+/i.test(String(url || '').trim());
}

/**
 * 仅向 Telegram 发送一条已拼好的 HTML 消息。
 * @param {Object} settings
 * @param {string} fullMessage
 * @returns {Promise<boolean>}
 */
async function sendTgRaw(settings, fullMessage) {
    if (!settings.BotToken || !settings.ChatID) {
        return false;
    }

    const url = `https://api.telegram.org/bot${settings.BotToken}/sendMessage`;
    const payload = {
        chat_id: settings.ChatID,
        text: fullMessage,
        parse_mode: 'HTML',
        disable_web_page_preview: true
    };

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            console.error('[NotificationService] TG API Error:', response.status, errorData);
        }

        return response.ok;
    } catch (error) {
        console.error('[NotificationService] TG Network Error:', error);
        return false;
    }
}

/**
 * 通过企业微信群机器人 Webhook 发送文本通知。
 * @param {Object} settings - 需含 WeComWebhookUrl
 * @param {string} message - 可为 HTML（会转纯文本）
 * @param {{ appendTimestamp?: boolean }} [options]
 * @returns {Promise<boolean>}
 */
export async function sendWeComNotification(settings, message, options = {}) {
    const { appendTimestamp = true } = options;
    const webhook = String(settings?.WeComWebhookUrl || '').trim();
    if (!webhook) {
        return false;
    }
    if (!isValidWeComWebhook(webhook)) {
        console.error('[NotificationService] Invalid WeCom webhook URL');
        return false;
    }

    let content = htmlToPlainText(message);
    if (appendTimestamp) {
        const now = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
        content = `${content}\n\n时间: ${now} (UTC+8)`;
    }
    // 企微 text 内容上限约 2048 字节，留余量截断
    if (content.length > 1800) {
        content = `${content.slice(0, 1800)}…`;
    }

    try {
        const response = await fetch(webhook, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                msgtype: 'text',
                text: { content }
            })
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok || data.errcode) {
            console.error('[NotificationService] WeCom API Error:', response.status, data);
            return false;
        }
        return true;
    } catch (error) {
        console.error('[NotificationService] WeCom Network Error:', error);
        return false;
    }
}

/**
 * 调试发送企业微信通知（返回详细错误）。
 * @param {Object} settings
 * @param {string} message
 */
export async function debugWeComNotification(settings, message) {
    const webhook = String(settings?.WeComWebhookUrl || '').trim();
    if (!webhook) {
        return { success: false, error: 'WeComWebhookUrl not configured' };
    }
    if (!isValidWeComWebhook(webhook)) {
        return { success: false, error: 'Invalid WeCom webhook URL' };
    }

    const now = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
    const content = `${htmlToPlainText(message)}\n\n时间: ${now} (UTC+8)`;

    try {
        const response = await fetch(webhook, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                msgtype: 'text',
                text: { content }
            })
        });
        const data = await response.json().catch(() => ({}));
        if (response.ok && !data.errcode) {
            return { success: true, response: data };
        }
        return {
            success: false,
            error: data.errmsg || `WeCom API Error: ${response.status}`,
            response: data
        };
    } catch (error) {
        return {
            success: false,
            error: `Network/Fetch Error: ${error.message}`
        };
    }
}

/**
 * 发送通知：Telegram（若已配置）与企业微信（若已配置）并行投递，任一成功即视为成功。
 * @param {Object} settings - 设置对象
 * @param {string} message - 消息内容 (支持部分 HTML 标签: <b>, <i>, <code>, <a>)
 * @returns {Promise<boolean>} - 是否至少有一个渠道发送成功
 */
export async function sendTgNotification(settings, message) {
    const now = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
    const fullMessage = `${message}\n\n<b>时间:</b> <code>${now} (UTC+8)</code>`;

    const [tgOk, wecomOk] = await Promise.all([
        sendTgRaw(settings, fullMessage),
        sendWeComNotification(settings, message, { appendTimestamp: true })
    ]);

    return tgOk || wecomOk;
}

/**
 * 增强版通知（含 IP 地理信息），同样会同步推到已配置的企微。
 * @param {Object} settings - 设置对象
 * @param {string} type - 通知类型 (支持 HTML)
 * @param {string} clientIp - 客户端IP
 * @param {string} additionalData - 额外数据 (支持 HTML)
 * @returns {Promise<boolean>} - 是否发送成功
 */
export async function sendEnhancedTgNotification(settings, type, clientIp, additionalData = '') {
    let locationInfo = '';

    try {
        const response = await fetch(`https://ipwho.is/${clientIp}`, {
            cf: { timeout: 3000 }
        });

        if (response.ok) {
            const ipInfo = await response.json();
            if (ipInfo.success) {
                locationInfo = `
<b>国家:</b> <code>${tgEscape(ipInfo.country || 'N/A')}</code>
<b>城市:</b> <code>${tgEscape(ipInfo.city || 'N/A')}</code>
<b>ISP:</b> <code>${tgEscape(ipInfo.connection?.org || ipInfo.connection?.isp || 'N/A')}</code>
<b>ASN:</b> <code>${tgEscape(ipInfo.connection?.asn ? 'AS' + ipInfo.connection.asn : 'N/A')}</code>`;
            }
        }
    } catch (error) {
        console.debug('[NotificationService] Failed to fetch IP geolocation:', error);
    }

    const now = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
    const message = `${type}

<b>IP 地址:</b> <code>${tgEscape(clientIp)}</code>${locationInfo}

${additionalData}

<b>时间:</b> <code>${now} (UTC+8)</code>`;

    const [tgOk, wecomOk] = await Promise.all([
        sendTgRaw(settings, message),
        sendWeComNotification(settings, message, { appendTimestamp: false })
    ]);

    return tgOk || wecomOk;
}

/**
 * 调试发送Telegram通知（返回详细错误信息）
 */
export async function debugTgNotification(settings, message) {
    if (!settings.BotToken || !settings.ChatID) {
        return { success: false, error: 'BotToken or ChatID not configured' };
    }

    const now = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
    const fullMessage = `${message}\n\n<b>时间:</b> <code>${now} (UTC+8)</code>`;

    const url = `https://api.telegram.org/bot${settings.BotToken}/sendMessage`;
    const payload = {
        chat_id: settings.ChatID,
        text: fullMessage,
        parse_mode: 'HTML',
        disable_web_page_preview: true
    };

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await response.json();

        if (response.ok) {
            return { success: true, response: data };
        } else {
            return {
                success: false,
                error: `Telegram API Error: ${response.status} ${response.statusText}`,
                response: data
            };
        }
    } catch (error) {
        return {
            success: false,
            error: `Network/Fetch Error: ${error.message}`
        };
    }
}
