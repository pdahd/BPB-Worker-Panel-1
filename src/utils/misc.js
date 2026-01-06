export function generateRemark(index, port, address, cleanIPs, protocol, configType) {
    let remark = '';
    let addressType;
    const type = configType ? ` ${configType}` : '';

    cleanIPs.includes(address)
        ? addressType = 'Clean IP'
        : addressType = isDomain(address) ? 'Domain': isIPv4(address) ? 'IPv4' : isIPv6(address) ? 'IPv6' : '';

    return `💦 ${index} - ${protocol}${type} - ${addressType} : ${port}`;
}

function isDomain(address) {
    const domainPattern = /^(?!\-)(?:[A-Za-z0-9\-]{1,63}\.?)+[A-Za-z]{2,}$/;
    return domainPattern.test(address);
}

function isIPv4(address) {
    const ipv4Pattern = /^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipv4Pattern.test(address);
}

export function isIPv6(address) {
    const ipv6Pattern = /^\[(?:(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|(?:[a-fA-F0-9]{1,4}:){1,7}:|::(?:[a-fA-F0-9]{1,4}:){0,7}|(?:[a-fA-F0-9]{1,4}:){1,6}:[a-fA-F0-9]{1,4}|(?:[a-fA-F0-9]{1,4}:){1,5}(?::[a-fA-F0-9]{1,4}){1,2}|(?:[a-fA-F0-9]{1,4}:){1,4}(?::[a-fA-F0-9]{1,4}){1,3}|(?:[a-fA-F0-9]{1,4}:){1,3}(?::[a-fA-F0-9]{1,4}){1,4}|(?:[a-fA-F0-9]{1,4}:){1,2}(?::[a-fA-F0-9]{1,4}){1,5}|[a-fA-F0-9]{1,4}:(?::[a-fA-F0-9]{1,4}){1,6})\]$/;
    return ipv6Pattern.test(address);
}

export function base64ToDecimal (base64) {
    const binaryString = atob(base64);
    const hexString = Array.from(binaryString).map(char => char.charCodeAt(0).toString(16).padStart(2, '0')).join('');
    const decimalArray = hexString.match(/.{2}/g).map(hex => parseInt(hex, 16));
    return decimalArray;
}

export async function getConfigAddresses(hostName, cleanIPs, enableIPv6, dohURL) {
    const resolved = await resolveDNS(hostName, dohURL);
    const defaultIPv6 = enableIPv6 ? resolved.ipv6.map((ip) => `[${ip}]`) : []
    return [
        hostName,
        'www.speedtest.net',
        ...resolved.ipv4,
        ...defaultIPv6,
        ...(cleanIPs ? cleanIPs.split(',') : [])
    ];
}

async function resolveDNS (domain, dohURL) {
    const dohURLv4 = `${dohURL}?name=${encodeURIComponent(domain)}&type=A`;
    const dohURLv6 = `${dohURL}?name=${encodeURIComponent(domain)}&type=AAAA`;

    try {
        const [ipv4Response, ipv6Response] = await Promise.all([
            fetch(dohURLv4, { headers: { accept: 'application/dns-json' } }),
            fetch(dohURLv6, { headers: { accept: 'application/dns-json' } })
        ]);

        const ipv4Addresses = await ipv4Response.json();
        const ipv6Addresses = await ipv6Response.json();

        const ipv4 = ipv4Addresses.Answer
            ? ipv4Addresses.Answer.map((record) => record.data)
            : [];
        const ipv6 = ipv6Addresses.Answer
            ? ipv6Addresses.Answer.map((record) => record.data)
            : [];

        return { ipv4, ipv6 };
    } catch (error) {
        console.error('Error resolving DNS:', error);
        throw new Error(`An error occurred while resolving DNS - ${error}`);
    }
}

export function randomUpperCase (str) {
    let result = '';
    for (let i = 0; i < str.length; i++) {
        result += Math.random() < 0.5 ? str[i].toUpperCase() : str[i];
    }
    return result;
}

export function getRandomPath (length) {
    let result = '';
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

export function isValidUUID(uuid) {
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return uuidRegex.test(uuid);
}

export const xrayConfigTemp = {
    remarks: "",
    log: {
        loglevel: "warning",
    },
    dns: {},
    fakedns: [
        {
            ipPool: "198.18.0.0/15",
            poolSize: 32768
        },
        {
            ipPool: "fc00::/18",
            poolSize: 32768
        }
    ],
    inbounds: [
        {
            port: 10808,
            protocol: "socks",
            settings: {
                auth: "noauth",
                udp: true,
                userLevel: 8,
            },
            sniffing: {
                destOverride: ["http", "tls"],
                enabled: true,
                routeOnly: true
            },
            tag: "socks-in",
        },
        {
            port: 10809,
            protocol: "http",
            settings: {
                auth: "noauth",
                udp: true,
                userLevel: 8,
            },
            sniffing: {
                destOverride: ["http", "tls"],
                enabled: true,
                routeOnly: true
            },
            tag: "http-in",
        },
        {
            listen: "127.0.0.1",
            port: 10853,
            protocol: "dokodemo-door",
            settings: {
              address: "1.1.1.1",
              network: "tcp,udp",
              port: 53
            },
            tag: "dns-in"
        }
    ],
    outbounds: [
        {
            tag: "fragment",
            protocol: "freedom",
            settings: {
                fragment: {
                    packets: "tlshello",
                    length: "",
                    interval: "",
                },
                domainStrategy: "UseIP"
            },
            streamSettings: {
                sockopt: {
                    tcpKeepAliveIdle: 100,
                    tcpNoDelay: true
                },
            },
        },
        {
            protocol: "dns",
            tag: "dns-out"
        },
        {
            protocol: "freedom",
            settings: {},
            tag: "direct",
        },
        {
            protocol: "blackhole",
            settings: {
                response: {
                    type: "http",
                },
            },
            tag: "block",
        },
    ],
    policy: {
        levels: {
            8: {
                connIdle: 300,
                downlinkOnly: 1,
                handshake: 4,
                uplinkOnly: 1,
            }
        },
        system: {
            statsOutboundUplink: true,
            statsOutboundDownlink: true,
        }
    },
    routing: {
        domainStrategy: "IPIfNonMatch",
        rules: [],
        balancers: [
            {
                tag: "all",
                selector: ["prox"],
                strategy: {
                    type: "leastPing",
                },
            }
        ]
    },
    observatory: {
        probeInterval: "30s",
        probeURL: "https://www.gstatic.com/generate_204",
        subjectSelector: ["prox"],
        EnableConcurrency: true,
    },
    stats: {}
};

export const singboxConfigTemp = {
    log: {
        level: "warn",
        timestamp: true
    },
    dns: {
        servers: [],
        rules: [],
        independent_cache: true
    },
    inbounds: [
        {
            type: "direct",
            tag: "dns-in",
            listen: "0.0.0.0",
            listen_port: 6450,
            override_address: "8.8.8.8",
            override_port: 53
        },
        {
            type: "tun",
            tag: "tun-in",
            inet4_address: "172.19.0.1/28",
            inet6_address: "fdfe:dcba:9876::1/126",
            mtu: 9000,
            auto_route: true,
            strict_route: true,
            stack: "mixed",
            sniff: true,
            sniff_override_destination: true
        },
        {
            type: "mixed",
            tag: "mixed-in",
            listen: "0.0.0.0",
            listen_port: 2080,
            sniff: true,
            sniff_override_destination: false
        }
    ],
    outbounds: [
        {
            type: "selector",
            tag: "proxy",
            outbounds: []
        },
        {
            type: "urltest",
            tag: "",
            outbounds: [],
            url: "https://www.gstatic.com/generate_204",
            interval: ""
        },
        {
            type: "direct",
            tag: "direct"
        },
        {
            type: "block",
            tag: "block"
        },
        {
            type: "dns",
            tag: "dns-out"
        }
    ],
    route: {
        rules: [],
        rule_set: [],
        auto_detect_interface: true,
        override_android_vpn: true,
        final: "proxy"
    },
    ntp: {
        enabled: true,
        server: "time.apple.com",
        server_port: 123,
        detour: "direct",
        interval: "30m",
    },
    experimental: {
        cache_file: {
            enabled: true,
            store_fakeip: true
        },
        clash_api: {
            external_controller: "0.0.0.0:9090",
            external_ui: "yacd",
            external_ui_download_url: "https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip",
            external_ui_download_detour: "direct",
            default_mode: "rule"
        }
    }
};

export const clashConfigTemp = {
    "mixed-port": 7890,
    "ipv6": true,
    "allow-lan": true,
    "mode": "rule",
    "log-level": "info",
    "keep-alive-interval": 30,
    "unified-delay": false,
    "dns": {},
    "tun": {
        "enable": true,
        "stack": "system",
        "auto-route": true,
        "auto-redirect": true,
        "auto-detect-interface": true,
        "dns-hijack": [
            "any:53",
            "198.18.0.2:53"
        ],
        "device": "utun0",
        "mtu": 9000,
        "strict-route": true
    },
    "sniffer": {
        "enable": true,
        "force-dns-mapping": true,
        "parse-pure-ip": true,
        "sniff": {
            "HTTP": {
                "ports": [80, 8080, 8880, 2052, 2082, 2086, 2095],
                "override-destination": false
            },
            "TLS": {
                "ports": [443, 8443, 2053, 2083, 2087, 2096],
                "override-destination": false
            }
        }
    },
    "proxies": [],
    "proxy-groups": [
        {
            "name": "✅ Selector",
            "type": "select",
            "proxies": []
        },
        {
            "name": "",
            "type": "url-test",
            "url": "https://www.gstatic.com/generate_204",
            "interval": 30,
            "tolerance": 50,
            "proxies": []
        }
    ],
    "rules": [],
    "ntp": {
        "enable": true,
        "server": "time.apple.com",
        "port": 123,
        "interval": 30
    }
};
