/**
 * 订阅链接测试工具
 * 用法: node test-subscription.js <订阅URL>
 */

import yaml from 'js-yaml';

/**
 * 检测字符串是否为有效的Base64格式
 */
function isValidBase64(str) {
	const cleanStr = str.replace(/\s/g, '');
	const base64Regex = /^[A-Za-z0-9+\/=]+$/;
	return base64Regex.test(cleanStr) && cleanStr.length > 10;
}

/**
 * 将 Clash 代理对象转换为标准节点链接
 */
function clashProxyToNodeLink(proxy) {
	try {
		const { name, server, port, type, cipher, password, uuid, tls, network } = proxy;
		const wsOpts = proxy['ws-opts'];

		if (!server || !port) return null;

		// Shadowsocks
		if (type === 'ss') {
			if (!cipher || !password) return null;
			const auth = `${cipher}:${password}`;
			const encoded = Buffer.from(auth).toString('base64');
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
			const encoded = Buffer.from(vmessJson).toString('base64');
			return `vmess://${encoded}`;
		}

		// Trojan
		if (type === 'trojan') {
			if (!password) return null;
			const nodeName = encodeURIComponent(name || 'Trojan Node');
			const tlsParam = tls === false ? '' : '?security=tls';
			return `trojan://${password}@${server}:${port}${tlsParam}#${nodeName}`;
		}

		return null;
	} catch (e) {
		return null;
	}
}

/**
 * 从 Clash YAML 配置中提取节点
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
		console.error('❌ YAML 解析失败:', e.message);
		return [];
	}
}

/**
 * 智能解码订阅内容，支持伪装格式和 Clash YAML
 */
function smartDecodeSubscription(text) {
	if (!text) return '';

	console.log('📥 原始内容长度:', text.length);
	console.log('📥 原始内容前100字符:', text.substring(0, 100));

	const nodeRegex = /^(ss|ssr|vmess|vless|trojan|hysteria2?|hy|hy2|tuic|anytls|socks5):\/\//;

	// 1. 先尝试按行分割，检查是否已经是节点列表
	const lines = text.replace(/\r\n/g, '\n').split('\n');
	const hasNodes = lines.some(line => nodeRegex.test(line.trim()));

	if (hasNodes) {
		console.log('✅ 内容已经是节点列表，无需解码');
		return text;
	}

	console.log('🔍 内容不是节点列表，尝试解码...');

	// 2. 检查是否为 Clash YAML 配置文件
	if (text.includes('proxies:') && (text.includes('port:') || text.includes('mode:'))) {
		console.log('🔍 检测到 Clash YAML 配置文件');
		try {
			const nodes = extractNodesFromClashYAML(text);
			if (nodes.length > 0) {
				console.log(`✅ 从 Clash 配置提取了 ${nodes.length} 个节点`);
				return nodes.join('\n');
			}
		} catch (e) {
			console.log('❌ Clash YAML 解析失败:', e.message);
		}
	}

	// 3. 尝试 Base64 解码
	try {
		const cleanedText = text.replace(/\s/g, '');
		console.log('🔍 检查是否为 Base64...');
		console.log('   - 清理后长度:', cleanedText.length);
		console.log('   - 是否有效 Base64 格式:', isValidBase64(cleanedText));

		if (isValidBase64(cleanedText)) {
			console.log('🔓 尝试 Base64 解码...');

			const decoded = Buffer.from(cleanedText, 'base64').toString('utf-8');
			console.log('✅ Base64 解码成功');
			console.log('📤 解码后长度:', decoded.length);
			console.log('📤 解码后前100字符:', decoded.substring(0, 100));

			// 验证解码后的内容是否包含节点
			const decodedLines = decoded.replace(/\r\n/g, '\n').split('\n');
			const hasDecodedNodes = decodedLines.some(line => nodeRegex.test(line.trim()));

			if (hasDecodedNodes) {
				console.log('✅ 解码后包含有效节点');
				return decoded;
			} else {
				console.log('⚠️  解码后不包含有效节点，检查是否为 Clash 配置');
				// 解码后可能也是 Clash 配置
				if (decoded.includes('proxies:')) {
					try {
						const nodes = extractNodesFromClashYAML(decoded);
						if (nodes.length > 0) {
							console.log(`✅ 从 Base64 解码的 Clash 配置提取了 ${nodes.length} 个节点`);
							return nodes.join('\n');
						}
					} catch (e) {
						console.log('❌ Base64 解码后的 Clash YAML 解析失败:', e.message);
					}
				}
			}
		}
	} catch (e) {
		console.log('❌ Base64 解码失败:', e.message);
	}

	// 4. 返回原始文本
	console.log('⚠️  使用原始内容');
	return text;
}

/**
 * 提取节点
 */
function extractNodes(text) {
	const nodeRegex = /^(ss|ssr|vmess|vless|trojan|hysteria2?|hy|hy2|tuic|anytls|socks5):\/\//;
	const lines = text.replace(/\r\n/g, '\n').split('\n');

	const nodes = lines
		.map(line => line.trim())
		.filter(line => nodeRegex.test(line));

	return nodes;
}

/**
 * 解析节点信息（简化版）
 */
function parseNodeInfo(nodeUrl) {
	try {
		const hashIndex = nodeUrl.lastIndexOf('#');
		const name = hashIndex !== -1
			? decodeURIComponent(nodeUrl.substring(hashIndex + 1))
			: '未命名节点';

		const protocolMatch = nodeUrl.match(/^(.*?):/);
		const protocol = protocolMatch ? protocolMatch[1].toUpperCase() : 'UNKNOWN';

		return { name, protocol };
	} catch (e) {
		return { name: '解析失败', protocol: 'UNKNOWN' };
	}
}

/**
 * 主测试函数
 */
async function testSubscription(url) {
	console.log('\n🚀 开始测试订阅链接');
	console.log('🔗 订阅URL:', url);
	console.log('━'.repeat(80) + '\n');

	try {
		// 1. 获取订阅内容
		console.log('📡 正在获取订阅内容...');

		// 智能选择 User-Agent
		let userAgent = 'v2rayN/6.45'; // 默认
		const urlLower = url.toLowerCase();
		if (urlLower.match(/\.(iso|jpg|jpeg|png|gif|zip|rar|pdf|doc|txt|yaml|yml)(\?|$)/i) ||
			urlLower.includes('clash') ||
			urlLower.includes('yaml')) {
			userAgent = 'v2rayN/6.45';
		}

		console.log('🔑 使用 User-Agent:', userAgent);

		const response = await fetch(url, {
			headers: {
				'User-Agent': userAgent
			},
			redirect: 'follow'
		});

		console.log('📊 响应状态:', response.status, response.statusText);
		console.log('📊 Content-Type:', response.headers.get('content-type'));
		console.log('📊 Content-Length:', response.headers.get('content-length'));

		if (!response.ok) {
			throw new Error(`HTTP ${response.status}: ${response.statusText}`);
		}

		const text = await response.text();

		// 2. 智能解码
		console.log('\n🔄 开始解码处理');
		const decoded = smartDecodeSubscription(text);

		// 3. 提取节点
		console.log('\n🔍 提取节点');
		const nodes = extractNodes(decoded);

		console.log('✅ 找到', nodes.length, '个节点\n');

		if (nodes.length === 0) {
			console.log('❌ 未找到任何有效节点');
			console.log('\n📋 解码后的内容预览 (前500字符):');
			console.log(decoded.substring(0, 500));
			return;
		}

		// 4. 显示节点信息
		console.log('📋 节点列表:');
		nodes.slice(0, 10).forEach((node, index) => {
			const info = parseNodeInfo(node);
			console.log(`  ${index + 1}. [${info.protocol}] ${info.name}`);
		});

		if (nodes.length > 10) {
			console.log(`  ... 还有 ${nodes.length - 10} 个节点 ...`);
		}

		// 5. 显示完整节点（前3个）
		console.log('\n📝 节点链接示例 (前3个):');
		nodes.slice(0, 3).forEach((node, index) => {
			console.log(`  ${index + 1}. ${node.substring(0, 80)}${node.length > 80 ? '...' : ''}`);
		});

		// 6. 统计
		console.log('\n📊 统计信息:');
		const protocolCount = {};
		nodes.forEach(node => {
			const match = node.match(/^(.*?):/);
			const protocol = match ? match[1].toUpperCase() : 'UNKNOWN';
			protocolCount[protocol] = (protocolCount[protocol] || 0) + 1;
		});

		Object.entries(protocolCount).forEach(([protocol, count]) => {
			console.log(`  ${protocol}: ${count} 个`);
		});

		console.log('\n✅ 测试完成！');

	} catch (error) {
		console.error('\n❌ 测试失败:', error.message);
		if (process.env.DEBUG) {
			console.error('\n堆栈信息:', error.stack);
		}
	}
}

// 执行测试
const url = process.argv[2];

if (!url) {
	console.log('\n用法: node test-subscription.js <订阅URL>');
	console.log('\n示例:');
	console.log('  node test-subscription.js "https://example.com/sub?token=xxx"');
	console.log('  node test-subscription.js "https://dler.cloud/api/v3/download.getFile/xxx.iso"');
	process.exit(1);
}

// 运行测试
testSubscription(url).catch(console.error);

