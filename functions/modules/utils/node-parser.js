/**
 * 节点解析工具模块
 * 提供节点URL解析和处理功能
 */

import yaml from 'js-yaml';
import { parseNodeInfo, extractNodeRegion } from './geo-utils.js';

/**
 * 支持的节点协议正则表达式
 */
export const NODE_PROTOCOL_REGEX = /^(ss|ssr|vmess|vless|trojan|hysteria2?|hy|hy2|tuic|anytls|socks5):\/\//g;

/**
 * 修复SS节点中的URL编码问题
 * @param {string} ssUrl - SS节点URL
 * @returns {string} 修复后的SS节点URL
 */
export function fixSSEncoding(ssUrl) {
    if (!ssUrl || !ssUrl.startsWith('ss://')) {
        return ssUrl;
    }

    try {
        const hashIndex = ssUrl.indexOf('#');
        let baseLink = hashIndex !== -1 ? ssUrl.substring(0, hashIndex) : ssUrl;
        let fragment = hashIndex !== -1 ? ssUrl.substring(hashIndex) : '';

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
        return baseLink + fragment;
    } catch (e) {
        // 如果处理失败，返回原始链接
        return ssUrl;
    }
}

/**
 * 修复vless和trojan节点中的URL编码问题
 * @param {string} nodeUrl - 节点URL
 * @returns {string} 修复后的节点URL
 */
export function fixNodeEncoding(nodeUrl) {
    if (!nodeUrl || typeof nodeUrl !== 'string') {
        return nodeUrl;
    }

    // 处理支持URL编码的协议
    const supportedProtocols = ['ss://', 'vless://', 'trojan://'];

    for (const protocol of supportedProtocols) {
        if (nodeUrl.startsWith(protocol)) {
            try {
                const hashIndex = nodeUrl.indexOf('#');
                let baseLink = hashIndex !== -1 ? nodeUrl.substring(0, hashIndex) : nodeUrl;
                let fragment = hashIndex !== -1 ? nodeUrl.substring(hashIndex) : '';

                // 检查base64部分是否包含URL编码字符
                const protocolEnd = baseLink.indexOf('://');
                const atIndex = baseLink.indexOf('@');
                if (protocolEnd !== -1 && atIndex !== -1) {
                    const base64Part = baseLink.substring(protocolEnd + 3, atIndex);
                    if (base64Part.includes('%')) {
                        // 解码URL编码的base64部分
                        const decodedBase64 = decodeURIComponent(base64Part);
                        baseLink = protocol + decodedBase64 + baseLink.substring(atIndex);
                    }
                }
                return baseLink + fragment;
            } catch (e) {
                // 如果处理失败，返回原始链接
                return nodeUrl;
            }
        }
    }

    return nodeUrl;
}

/**
 * 从文本中提取所有有效的节点URL
 * @param {string} text - 包含节点的文本
 * @returns {string[]} 有效的节点URL数组
 */
export function extractValidNodes(text) {
    if (!text || typeof text !== 'string') {
        return [];
    }

    // 标准化换行符并分割文本
    const lines = text
        .replace(/\r\n/g, '\n')
        .split('\n')
        .map(line => line.trim())
        .filter(line => NODE_PROTOCOL_REGEX.test(line));

    // 修复每个节点的编码问题
    return lines.map(nodeUrl => fixNodeEncoding(nodeUrl));
}

/**
 * Base64解码文本
 * @param {string} text - 要解码的文本
 * @returns {string} 解码后的文本
 */
export function decodeBase64Text(text) {
    if (!text || typeof text !== 'string') {
        return text;
    }

    try {
        const cleanedText = text.replace(/\s/g, '');

        // 简单的Base64格式检查
        const base64Regex = /^[A-Za-z0-9+\/=]+$/;
        if (!base64Regex.test(cleanedText) || cleanedText.length < 20) {
            return text;
        }

        // 尝试Base64解码
        const binaryString = atob(cleanedText);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return new TextDecoder('utf-8').decode(bytes);
    } catch (e) {
        // Base64解码失败，返回原始内容
        return text;
    }
}

/**
 * 智能内容类型检测
 * @param {string} text - 要检测的文本内容
 * @returns {string} 内容类型描述
 */
export function detectContentType(text) {
    if (!text || typeof text !== 'string') {
        return 'unknown';
    }

    if (text.includes('proxies:') && text.includes('rules:')) {
        return 'clash-config';
    }

    if (text.includes('outbounds') && text.includes('inbounds') && text.includes('route')) {
        return 'singbox-config';
    }

    // 检查是否包含节点URL
    const nodeCount = (text.match(NODE_PROTOCOL_REGEX) || []).length;
    if (nodeCount > 0) {
        return 'node-list';
    }

    return 'unknown';
}

/**
 * 解析节点列表
 * @param {string} content - 包含节点的文本内容
 * @returns {Array} 解析后的节点对象数组
 */
export function parseNodeList(content) {
    if (!content) {
        return [];
    }

    // 检测内容类型
    const contentType = detectContentType(content);

    // 如果是完整的配置文件，不处理节点
    if (contentType === 'clash-config' || contentType === 'singbox-config') {
        return [];
    }

    // 尝试Base64解码
    let processedContent = content;
    try {
        processedContent = decodeBase64Text(content);
    } catch (e) {
        // 解码失败，使用原始内容
    }

    // 提取有效节点
    const validNodes = extractValidNodes(processedContent);

    // 解析每个节点的详细信息
    return validNodes.map(nodeUrl => {
        const nodeInfo = parseNodeInfo(nodeUrl);
        return {
            url: nodeUrl,
            ...nodeInfo
        };
    });
}

/**
 * 统计节点协议类型分布
 * @param {Array} nodes - 节点数组
 * @returns {Object} 协议统计信息
 */
export function calculateProtocolStats(nodes) {
    const stats = {};
    const total = nodes.length;

    nodes.forEach(node => {
        const protocol = node.protocol || 'unknown';
        stats[protocol] = (stats[protocol] || 0) + 1;
    });

    // 添加百分比信息
    for (const [protocol, count] of Object.entries(stats)) {
        stats[protocol] = {
            count,
            percentage: Math.round((count / total) * 100)
        };
    }

    return stats;
}

/**
 * 统计节点地区分布
 * @param {Array} nodes - 节点数组
 * @returns {Object} 地区统计信息
 */
export function calculateRegionStats(nodes) {
    const stats = {};
    const total = nodes.length;

    nodes.forEach(node => {
        const region = extractNodeRegion(node.name || '');
        stats[region] = (stats[region] || 0) + 1;
    });

    // 添加百分比信息
    for (const [region, count] of Object.entries(stats)) {
        stats[region] = {
            count,
            percentage: Math.round((count / total) * 100)
        };
    }

    return stats;
}

/**
 * 去除重复节点
 * @param {Array} nodes - 节点数组
 * @returns {Array} 去重后的节点数组
 */
export function removeDuplicateNodes(nodes) {
    if (!Array.isArray(nodes)) {
        return [];
    }

    const seen = new Set();
    return nodes.filter(node => {
        const url = node.url || '';
        if (seen.has(url)) {
            return false;
        }
        seen.add(url);
        return true;
    });
}

/**
 * 根据地区对节点进行排序
 * @param {Array} nodes - 节点数组
 * @returns {Array} 排序后的节点数组
 */
export function sortNodesByRegion(nodes) {
    if (!Array.isArray(nodes)) {
        return nodes;
    }

    const regionOrder = [
        '香港', '台湾', '新加坡', '日本', '美国', '韩国',
        '英国', '德国', '法国', '加拿大', '澳大利亚',
        '荷兰', '俄罗斯', '印度', '土耳其', '马来西亚',
        '泰国', '越南', '菲律宾', '印尼', '其他'
    ];

    return nodes.sort((a, b) => {
        const aRegionIndex = regionOrder.indexOf(a.region);
        const bRegionIndex = regionOrder.indexOf(b.region);

        // 如果地区相同，按名称排序
        if (aRegionIndex === bRegionIndex) {
            return a.name.localeCompare(b.name);
        }

        return aRegionIndex - bRegionIndex;
    });
}

/**
 * 格式化节点数量显示
 * @param {number} count - 节点数量
 * @returns {string} 格式化后的显示文本
 */
export function formatNodeCount(count) {
    if (typeof count !== 'number' || count < 0) {
        return '0 个节点';
    }

    return `${count} 个节点`;
}

/**
 * 验证节点URL格式
 * @param {string} nodeUrl - 节点URL
 * @returns {boolean} 是否为有效的节点URL
 */
export function isValidNodeUrl(nodeUrl) {
    if (!nodeUrl || typeof nodeUrl !== 'string') {
        return false;
    }

    return NODE_PROTOCOL_REGEX.test(nodeUrl.trim());
}

/**
 * 清理节点名称
 * @param {string} nodeName - 原始节点名称
 * @returns {string} 清理后的节点名称
 */
export function cleanNodeName(nodeName) {
    if (!nodeName || typeof nodeName !== 'string') {
        return '';
    }

    return nodeName
        .trim()
        .replace(/\s+/g, ' ') // 合并多余空格
        .replace(/[^\w\s\-_().[\]{}]/g, ''); // 移除特殊字符，保留基本字符
}

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

        return nodes;
    } catch (e) {
        return [];
    }
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
export function smartDecodeSubscription(text) {
    if (!text) return '';

    const nodeRegex = /^(ss|ssr|vmess|vless|trojan|hysteria2?|hy|hy2|tuic|anytls|socks5):\/\//;

    // 1. 先尝试按行分割，检查是否已经是节点列表
    const lines = text.replace(/\r\n/g, '\n').split('\n');
    const hasNodes = lines.some(line => nodeRegex.test(line.trim()));

    if (hasNodes) {
        return text;
    }

    // 2. 检查是否为 Clash YAML 配置文件
    if (text.includes('proxies:') && (text.includes('port:') || text.includes('mode:'))) {
        try {
            const nodes = extractNodesFromClashYAML(text);
            if (nodes.length > 0) {
                return nodes.join('\n');
            }
        } catch (e) {
            // Clash YAML 解析失败，继续尝试其他方式
        }
    }

    // 3. 尝试 Base64 解码
    try {
        const cleanedText = text.replace(/\s/g, '');
        const isBase64 = isValidBase64(cleanedText);

        if (isBase64) {
            const binaryString = atob(cleanedText);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            const decoded = new TextDecoder('utf-8', { fatal: false }).decode(bytes);

            // 验证解码后的内容是否包含节点
            const decodedLines = decoded.replace(/\r\n/g, '\n').split('\n');
            const hasDecodedNodes = decodedLines.some(line => nodeRegex.test(line.trim()));

            if (hasDecodedNodes) {
                return decoded;
            } else {
                // 解码后可能也是 Clash 配置
                if (decoded.includes('proxies:')) {
                    try {
                        const nodes = extractNodesFromClashYAML(decoded);
                        if (nodes.length > 0) {
                            return nodes.join('\n');
                        }
                    } catch (e) {
                        // Base64 解码后的 Clash YAML 解析失败
                    }
                }
            }
        }
    } catch (e) {
        // Base64 解码失败，继续尝试其他方式
    }

    // 4. 如果文本看起来像二进制数据，尝试直接作为 UTF-8 解析
    if (text.includes('\x00') || text.charCodeAt(0) > 127) {
        try {
            const encoder = new TextEncoder();
            const bytes = encoder.encode(text);
            const decoded = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
            const decodedLines = decoded.replace(/\r\n/g, '\n').split('\n');
            const hasDecodedNodes = decodedLines.some(line => nodeRegex.test(line.trim()));

            if (hasDecodedNodes) {
                return decoded;
            }
        } catch (e) {
            // 二进制解析失败
        }
    }

    // 5. 返回原始文本
    return text;
}