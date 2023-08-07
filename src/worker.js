const resolveDNS = async (domain) => {
	const types = [
		'A',
		'AAAA',
		'CNAME',
		'TXT',
		'SPF',
		'MX',
		'NS',
		'SRV',
		'PTR',
		'NAPTR',
		'SOA',
		'CAA',
		'HINFO',
		'SSHFP',
		'TLSA',
		'DNSKEY',
		'DS',
		'RRSIG',
		'NSEC',
		'NSEC3',
		'NSEC3PARAM',
		'OPT',
	];
	const dnsResults = {};

	for (const type of types) {
		const dnsEndpoint = `https://1.1.1.1/dns-query?name=${domain}&type=${type}`;
		// https://cloudflare-dns.com/dns-query?name=${domain}&type=${type}

		const response = await fetch(dnsEndpoint, {
			headers: {
				Accept: 'application/dns-json',
			},
		});

		if (response.ok) {
			const data = await response.json();
			if (data.Answer) {
				dnsResults[type] = data.Answer.map((entry) => ({
					name: entry.name, // The domain name being queried
					type: entry.type, // The DNS record type (e.g., A, AAAA, MX, TXT, etc.)
					TTL: entry.TTL, // Time to Live - how long the record can be cached by other DNS servers
					data: entry.data, // The actual value associated with the DNS record (e.g., IP address)
					class: entry.class, // DNS class (usually IN for Internet)
					flushFlag: entry.flush, // Whether the record is marked as "flushable"
					priority: entry.priority, // Priority value (usually for MX records)
					weight: entry.weight, // Weight value (usually for MX records)
					port: entry.port, // Port number (usually for SRV records)
					target: entry.target, // Target domain (usually for CNAME, MX, and SRV records)
					protocol: entry.protocol, // Protocol information (usually for SRV records)
					service: entry.service, // Service information (usually for SRV records)
					domain: entry.domain, // Domain information (usually for NAPTR records)
					flags: entry.flags, // Flags associated with the DNS record (usually for NAPTR records)
					regexp: entry.regexp, // Regular expression (usually for NAPTR records)
					replacement: entry.replacement, // Replacement value (usually for NAPTR records)
				}));
			} else {
				dnsResults[type] = [];
			}
		} else {
			dnsResults[type] = [];
		}
	}

	return dnsResults;
};

const fetchWebsiteInfo = async (domain) => {
	const response = await fetch(`https://${domain}`);

	const headers = {};
	response.headers.forEach((value, key) => {
		headers[key] = value;
	});

	const httpInfo = {
		status: response.status,
		statusText: response.statusText,
		headers: headers,
	};

	return httpInfo;
};

const analyzeSecurityHeaders = (headers) => {
	const securityHeaders = {
		'Strict-Transport-Security': '',
		'Content-Security-Policy': '',
		'X-Frame-Options': '',
		'X-XSS-Protection': '',
		'X-Content-Type-Options': '',
		'Referrer-Policy': '',
		'X-Powered-By': '',
		Server: '',
	};

	if ('strict-transport-security' in headers) {
		securityHeaders['Strict-Transport-Security'] = headers['strict-transport-security'];
	}

	if ('content-security-policy' in headers) {
		securityHeaders['Content-Security-Policy'] = headers['content-security-policy'];
	}

	if ('x-frame-options' in headers) {
		securityHeaders['X-Frame-Options'] = headers['x-frame-options'];
	}

	if ('x-xss-protection' in headers) {
		securityHeaders['X-XSS-Protection'] = headers['x-xss-protection'];
	}

	if ('x-content-type-options' in headers) {
		securityHeaders['X-Content-Type-Options'] = headers['x-content-type-options'];
	}

	if ('referrer-policy' in headers) {
		securityHeaders['Referrer-Policy'] = headers['referrer-policy'];
	}

	if ('x-powered-by' in headers) {
		securityHeaders['X-Powered-By'] = headers['x-powered-by'];
	}

	if ('server' in headers) {
		securityHeaders['Server'] = headers['server'];
	}

	return securityHeaders;
};

const getTLSInfo = (request) => {
	const cfProperties = request.cf;
	const tlsVersion = cfProperties.tlsVersion;
	const cipherSuite = cfProperties.tlsCipher;
	const httpProtocol = cfProperties.httpProtocol;
	const colo = cfProperties.colo;

	return {
		httpProtocol,
		tlsVersion,
		cipherSuite,
		colo,
	};
};

export default {
	async fetch(request) {
		const url = new URL(request.url);
		const targetDomain = url.searchParams.get('domain');

		if (!targetDomain) {
			return new Response('Missing domain parameter... Example: https://webscanner-research.cf-testing.workers.dev/?domain=cf-testing.com', { status: 400 });
		}

		try {
			const dnsResults = await resolveDNS(targetDomain);
			const httpInfo = await fetchWebsiteInfo(targetDomain);
			const securityHeaders = analyzeSecurityHeaders(httpInfo.headers);
			const securityHandshake = getTLSInfo(request);

			const result = {
				domain: targetDomain,
				dns: dnsResults,
				http: httpInfo,
				securityHeaders: securityHeaders,
				securityHandshake: securityHandshake,
			};

			return new Response(JSON.stringify(result, null, 2), {
				headers: { 'Content-Type': 'application/json' },
			});
		} catch (error) {
			return new Response(`An error occurred... + ${error}`, { status: 500 });
		}
	},
};
