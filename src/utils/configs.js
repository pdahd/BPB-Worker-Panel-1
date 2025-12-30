import {
    generateRemark,
    isIPv6,
    base64ToDecimal,
    xrayConfigTemp,
    singboxConfigTemp,
    clashConfigTemp,
    getConfigAddresses,
    randomUpperCase,
    getRandomPath,
    isDomain,
    resolveDNS,
    extractWireguardParams
} from './misc.js';

async function buildXrayDNS (proxySettings, outboundAddrs, domainToStaticIPs, isWorkerLess, isWarp, dohURL) {
    const {
        remoteDNS,
        resolvedRemoteDNS,
        localDNS,
        vlessTrojanFakeDNS,
        warpFakeDNS,
        blockAds,
        bypassIran,
        bypassChina,
        blockPorn,
        bypassRussia
    } = proxySettings;

    const isBypass = bypassIran || bypassChina || bypassRussia;
    const isFakeDNS = (vlessTrojanFakeDNS && !isWarp) || (warpFakeDNS && isWarp);
    const outboundDomains = outboundAddrs.filter(address => isDomain(address));
    const isOutboundRule = outboundDomains.length > 0;
    const outboundRules = outboundDomains.map(domain => `full:${domain}`);
    const finalRemoteDNS = isWarp
        ? ['1.1.1.1', '1.0.0.1']
        : isWorkerLess
            ? ['https://cloudflare-dns.com/dns-query']
            : [remoteDNS];

    let dnsObject = {
        hosts: {
            "domain:googleapis.cn": ["googleapis.com"]
        },
        servers: finalRemoteDNS,
        tag: "dns",
    };

    const staticIPs = domainToStaticIPs ? await resolveDNS(domainToStaticIPs, dohURL) : undefined;
    if (staticIPs) dnsObject.hosts[domainToStaticIPs] = [...staticIPs.ipv4, ...staticIPs.ipv6];
    if (resolvedRemoteDNS.server && !isWorkerLess && !isWarp) dnsObject.hosts[resolvedRemoteDNS.server] = resolvedRemoteDNS.staticIPs;
    if (isWorkerLess) {
        const resolvedDOH = await resolveDNS('cloudflare-dns.com', dohURL);
        const resolvedCloudflare = await resolveDNS('cloudflare.com', dohURL);
        const resolvedCLDomain = await resolveDNS('www.speedtest.net.cdn.cloudflare.net', dohURL);
        const resolvedCFNS_1 = await resolveDNS('ben.ns.cloudflare.com', dohURL);
        const resolvedCFNS_2 = await resolveDNS('lara.ns.cloudflare.com', dohURL);
        dnsObject.hosts['cloudflare-dns.com'] = [
            ...resolvedDOH.ipv4,
            ...resolvedCloudflare.ipv4,
            ...resolvedCLDomain.ipv4,
            ...resolvedCFNS_1.ipv4,
            ...resolvedCFNS_2.ipv4
        ];
    }

    if (blockAds) {
        dnsObject.hosts["geosite:category-ads-all"] = ["127.0.0.1"];
        dnsObject.hosts["geosite:category-ads-ir"] = ["127.0.0.1"];
    }

    if (blockPorn) {
        dnsObject.hosts["geosite:category-porn"] = ["127.0.0.1"];
    }

    isOutboundRule && dnsObject.servers.push({
        address: localDNS === 'localhost' ? '8.8.8.8' : localDNS,
        domains: outboundRules
    });

    let localDNSServer = {
        address: localDNS,
        domains: [],
        expectIPs: []
    };

    if (!isWorkerLess && isBypass) {
        bypassIran && localDNSServer.domains.push("geosite:category-ir") && localDNSServer.expectIPs.push("geoip:ir");
        bypassChina && localDNSServer.domains.push("geosite:cn") && localDNSServer.expectIPs.push("geoip:cn");
        bypassRussia && localDNSServer.domains.push("geosite:category-ru") && localDNSServer.expectIPs.push("geoip:ru");
        dnsObject.servers.push(localDNSServer);
    }

    if (isFakeDNS) {
        if ((isBypass || isOutboundRule) && !isWorkerLess) {
            dnsObject.servers.unshift({
                address: "fakedns",
                domains: [
                    ...localDNSServer.domains,
                    ...outboundRules
                ]
            });
        } else {
            dnsObject.servers.unshift("fakedns");
        }
    }

    return dnsObject;
}

function buildXrayRoutingRules (proxySettings, outboundAddrs, isChain, isBalancer, isWorkerLess) {
    const {
        localDNS,
        bypassLAN,
        bypassIran,
        bypassChina,
        bypassRussia,
        blockAds,
        blockPorn,
        blockUDP443
    } = proxySettings;

    const isBypass = bypassIran || bypassChina || bypassRussia || bypassLAN;
    const outboundDomains = outboundAddrs.filter(address => isDomain(address));
    const isOutboundRule = outboundDomains.length > 0;
    let rules = [
        {
            inboundTag: [
                "dns-in"
            ],
            outboundTag: "dns-out",
            type: "field"
        },
        {
            inboundTag: [
                "socks-in",
                "http-in"
            ],
            port: "53",
            outboundTag: "dns-out",
            type: "field"
        }
    ];

    if (!isWorkerLess && (isOutboundRule || (localDNS !== 'localhost' && isBypass))) rules.push({
        ip: [localDNS === 'localhost' ? '8.8.8.8' : localDNS],
        port: "53",
        outboundTag: "direct",
        type: "field"
    });

    if (isBypass && !isWorkerLess) {
        let ipRule = {
            ip: [],
            outboundTag: "direct",
            type: "field",
        };

        let domainRule = {
            domain: [],
            outboundTag: "direct",
            type: "field",
        };

        bypassLAN && domainRule.domain.push("geosite:private") && ipRule.ip.push("geoip:private");
        bypassIran && domainRule.domain.push("geosite:category-ir") && ipRule.ip.push("geoip:ir");
        bypassChina && domainRule.domain.push("geosite:cn") && ipRule.ip.push("geoip:cn");
        bypassRussia && domainRule.domain.push("geosite:category-ru") && ipRule.ip.push("geoip:ru");
        rules.push(domainRule, ipRule);
    }

    blockUDP443 && rules.push({
        network: "udp",
        port: "443",
        outboundTag: "block",
        type: "field",
    });

    if (blockAds || blockPorn) {
        let rule = {
            domain: [],
            outboundTag: "block",
            type: "field",
        };

        blockAds && rule.domain.push("geosite:category-ads-all", "geosite:category-ads-ir");
        blockPorn && rule.domain.push("geosite:category-porn");
        rules.push(rule);
    }

    if (isBalancer) {
        rules.push({
            network: "tcp,udp",
            balancerTag: "all",
            type: "field"
        });
    } else  {
        rules.push({
            network: "tcp,udp",
            outboundTag: isChain ? "chain" : isWorkerLess ? "fragment" : "proxy",
            type: "field"
        });
    }

    return rules;
}

function buildXrayVLESSOutbound (tag, address, port, host, sni, proxyIP, isFragment, allowInsecure, userID, defaultHttpsPorts) {
    let outbound = {
        protocol: "vless",
        settings: {
            vnext: [
                {
                    address: address,
                    port: +port,
                    users: [
                        {
                            id: userID,
                            encryption: "none",
                            level: 8
                        }
                    ]
                }
            ]
        },
        streamSettings: {
            network: "ws",
            security: "none",
            sockopt: {},
            wsSettings: {
                headers: {
                    Host: host,
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
                },
                path: `/${getRandomPath(16)}${proxyIP ? `/${btoa(proxyIP)}` : ''}?ed=2560`
            }
        },
        tag: tag
    };

    if (defaultHttpsPorts.includes(port)) {
        outbound.streamSettings.security = "tls";
        outbound.streamSettings.tlsSettings = {
            allowInsecure: allowInsecure,
            fingerprint: "randomized",
            alpn: ["h2", "http/1.1"],
            serverName: sni
        };
    }

    if (isFragment) {
        outbound.streamSettings.sockopt.dialerProxy = "fragment";
    } else {
        outbound.streamSettings.sockopt.tcpKeepAliveIdle = 100;
        outbound.streamSettings.sockopt.tcpNoDelay = true;
    }

    return outbound;
}

function buildXrayTrojanOutbound (tag, address, port, host, sni, proxyIP, isFragment, allowInsecure, trojanPassword, defaultHttpsPorts) {
    let outbound = {
        protocol: "trojan",
        settings: {
            servers: [
                {
                    address: address,
                    port: +port,
                    password: trojanPassword,
                    level: 8
                }
            ]
        },
        streamSettings: {
            network: "ws",
            security: "none",
            sockopt: {},
            wsSettings: {
                headers: {
                    Host: host
                },
                path: `/tr${getRandomPath(16)}${proxyIP ? `/${btoa(proxyIP)}` : ''}?ed=2560`
            }
        },
        tag: tag
    };

    if (defaultHttpsPorts.includes(port)) {
        outbound.streamSettings.security = "tls";
        outbound.streamSettings.tlsSettings = {
            allowInsecure: allowInsecure,
            fingerprint: "randomized",
            alpn: ["h2", "http/1.1"],
            serverName: sni
        };
    }

    if (isFragment) {
        outbound.streamSettings.sockopt.dialerProxy = "fragment";
    } else {
        outbound.streamSettings.sockopt.tcpKeepAliveIdle = 100;
        outbound.streamSettings.sockopt.tcpNoDelay = true;
    }

    return outbound;
}

function buildXrayWarpOutbound (proxySettings, warpConfigs, endpoint, isChain, client) {
    const {
		nikaNGNoiseMode,
		noiseCountMin,
		noiseCountMax,
		noiseSizeMin,
		noiseSizeMax,
		noiseDelayMin,
		noiseDelayMax
	} = proxySettings;

    const {
        warpIPv6,
        reserved,
        publicKey,
        privateKey
    } = extractWireguardParams(warpConfigs, isChain);

    let outbound = {
        protocol: "wireguard",
        settings: {
            address: [
                "172.16.0.2/32",
                warpIPv6
            ],
            mtu: 1280,
            peers: [
                {
                    endpoint: endpoint,
                    publicKey: publicKey,
                    keepAlive: 5
                }
            ],
            reserved: base64ToDecimal(reserved),
            secretKey: privateKey
        },
        streamSettings: {
            sockopt: {
                dialerProxy: "proxy",
                tcpKeepAliveIdle: 100,
                tcpNoDelay: true,
            }
        },
        tag: isChain ? "chain" : "proxy"
    };

    !isChain && delete outbound.streamSettings;
    client === 'nikang' && !isChain && Object.assign(outbound.settings, {
        wnoise: nikaNGNoiseMode,
        wnoisecount: noiseCountMin === noiseCountMax ? noiseCountMin : `${noiseCountMin}-${noiseCountMax}`,
        wpayloadsize: noiseSizeMin === noiseSizeMax ? noiseSizeMin : `${noiseSizeMin}-${noiseSizeMax}`,
        wnoisedelay: noiseDelayMin === noiseDelayMax ? noiseDelayMin : `${noiseDelayMin}-${noiseDelayMax}`
    });

    return outbound;
}

function buildXrayChainOutbound(chainProxyParams) {
    if (['socks', 'http'].includes(chainProxyParams.protocol)) {
        const { protocol, host, port, user, pass } = chainProxyParams;
        return {
            protocol: protocol,
            settings: {
                servers: [
                    {
                        address: host,
                        port: +port,
                        users: [
                            {
                                user: user,
                                pass: pass,
                                level: 8
                            }
                        ]
                    }
                ]
            },
            streamSettings: {
                network: "tcp",
                sockopt: {
                    dialerProxy: "proxy",
                    tcpNoDelay: true
                }
            },
            mux: {
                enabled: true,
                concurrency: 8,
                xudpConcurrency: 16,
                xudpProxyUDP443: "reject"
            },
            tag: "chain"
        };
    }

    const {
        hostName,
        port,
        uuid,
        flow,
        security,
        type,
        sni,
        fp,
        alpn,
        pbk,
        sid,
        spx,
        headerType,
        host,
        path,
        authority,
        serviceName,
        mode
    } = chainProxyParams;

    let proxyOutbound = {
        mux: {
            concurrency: 8,
            enabled: true,
            xudpConcurrency: 16,
            xudpProxyUDP443: "reject"
        },
        protocol: "vless",
        settings: {
            vnext: [
                {
                    address: hostName,
                    port: +port,
                    users: [
                        {
                            encryption: "none",
                            flow: flow,
                            id: uuid,
                            level: 8,
                            security: "auto"
                        }
                    ]
                }
            ]
        },
        streamSettings: {
            network: type,
            security: security,
            sockopt: {
                dialerProxy: "proxy",
                tcpNoDelay: true
            }
        },
        tag: "chain"
    };

    if (security === 'tls') {
        const tlsAlpns = alpn ? alpn?.split(',') : [];
        proxyOutbound.streamSettings.tlsSettings = {
            allowInsecure: false,
            fingerprint: fp,
            alpn: tlsAlpns,
            serverName: sni
        };
    }

    if (security === 'reality') {
        delete proxyOutbound.mux;
        proxyOutbound.streamSettings.realitySettings = {
            fingerprint: fp,
            publicKey: pbk,
            serverName: sni,
            shortId: sid,
            spiderX: spx
        };
    }

    if (headerType === 'http') {
        const httpPaths = path?.split(',');
        const httpHosts = host?.split(',');
        proxyOutbound.streamSettings.tcpSettings = {
            header: {
                request: {
                    headers: { Host: httpHosts },
                    method: "GET",
                    path: httpPaths,
                    version: "1.1"
                },
                response: {
                    headers: { "Content-Type": ["application/octet-stream"] },
                    reason: "OK",
                    status: "200",
                    version: "1.1"
                },
                type: "http"
            }
        };
    }

    if (type === 'tcp' && security !== 'reality' && !headerType) proxyOutbound.streamSettings.tcpSettings = {
        header: {
            type: "none"
        }
    };

    if (type === 'ws') proxyOutbound.streamSettings.wsSettings = {
        headers: { Host: host },
        path: path
    };

    if (type === 'grpc') {
        delete proxyOutbound.mux;
        proxyOutbound.streamSettings.grpcSettings = {
            authority: authority,
            multiMode: mode === 'multi',
            serviceName: serviceName
        };
    }

    return proxyOutbound;
}

function buildXrayConfig (proxySettings, remark, isFragment, isBalancer, isChain, balancerFallback, isWarp) {
    const {
        vlessTrojanFakeDNS,
        warpFakeDNS,
        bestVLESSTrojanInterval,
        bestWarpInterval,
        lengthMin,
        lengthMax,
        intervalMin,
        intervalMax,
        fragmentPackets
    } = proxySettings;

    const isFakeDNS = (vlessTrojanFakeDNS && !isWarp) || (warpFakeDNS && isWarp);
    let config = structuredClone(xrayConfigTemp);
    config.remarks = remark;
    if (isFakeDNS) {
        config.inbounds[0].sniffing.destOverride.push("fakedns");
        config.inbounds[1].sniffing.destOverride.push("fakedns");
    } else {
        delete config.fakedns;
    }

    if (isFragment) {
        const fragment = config.outbounds[0].settings.fragment;
        fragment.length = `${lengthMin}-${lengthMax}`;
        fragment.interval = `${intervalMin}-${intervalMax}`;
        fragment.packets = fragmentPackets;
    } else {
        config.outbounds.shift();
    }

    if (isBalancer) {
        const interval = isWarp ? bestWarpInterval : bestVLESSTrojanInterval;
        config.observatory.probeInterval = `${interval}s`;
        config.observatory.subjectSelector = [isChain ? 'chain' : 'prox'];
        config.routing.balancers[0].selector = [isChain ? 'chain' : 'prox'];
        if (balancerFallback) config.routing.balancers[0].fallbackTag = balancerFallback;
    } else {
        delete config.observatory;
        delete config.routing.balancers;
    }

    return config;
}

async function buildXrayBestPingConfig(proxySettings, totalAddresses, chainProxy, outbounds, isFragment, dohURL) {
    const remark = isFragment ? '💦 BPB F - Best Ping 💥' : '💦 BPB - Best Ping 💥';
    let config = buildXrayConfig(proxySettings, remark, isFragment, true, chainProxy, chainProxy ? 'chain-2' : 'prox-2');
    config.dns = await buildXrayDNS(proxySettings, totalAddresses, undefined, false, false, dohURL);
    config.routing.rules = buildXrayRoutingRules(proxySettings, totalAddresses, chainProxy, true, false);
    config.outbounds.unshift(...outbounds);

    return config;
}

async function buildXrayBestFragmentConfig(proxySettings, hostName, chainProxy, outbounds, dohURL) {
    const bestFragValues = ['10-20', '20-30', '30-40', '40-50', '50-60', '60-70',
                            '70-80', '80-90', '90-100', '10-30', '20-40', '30-50',
                            '40-60', '50-70', '60-80', '70-90', '80-100', '100-200'];

    let config = buildXrayConfig(proxySettings, '💦 BPB F - Best Fragment 😎', true, true, chainProxy, undefined, false);
    config.dns = await buildXrayDNS(proxySettings, [], hostName, false, false, dohURL);
    config.routing.rules = buildXrayRoutingRules(proxySettings, [], chainProxy, true, false);
    const fragment = config.outbounds.shift();
    let bestFragOutbounds = [];

    bestFragValues.forEach( (fragLength, index) => {
        if (chainProxy) {
            let chainOutbound = structuredClone(chainProxy);
            chainOutbound.tag = `chain-${index + 1}`;
            chainOutbound.streamSettings.sockopt.dialerProxy = `prox-${index + 1}`;
            bestFragOutbounds.push(chainOutbound);
        }

        let proxyOutbound = structuredClone(outbounds[chainProxy ? 1 : 0]);
        proxyOutbound.tag = `prox-${index + 1}`;
        proxyOutbound.streamSettings.sockopt.dialerProxy = `frag-${index + 1}`;
        let fragmentOutbound = structuredClone(fragment);
        fragmentOutbound.tag = `frag-${index + 1}`;
        fragmentOutbound.settings.fragment.length = fragLength;
        fragmentOutbound.settings.fragment.interval = '1-1';
        bestFragOutbounds.push(proxyOutbound, fragmentOutbound);
    });

    config.outbounds.unshift(...bestFragOutbounds);
    return config;
}

async function buildXrayWorkerLessConfig(proxySettings, userID, dohURL, defaultHttpsPorts) {
    let config = buildXrayConfig(proxySettings, '💦 BPB F - WorkerLess ⭐', true, false, false, undefined, false);
    config.dns = await buildXrayDNS(proxySettings, [], undefined, true, false, dohURL);
    config.routing.rules = buildXrayRoutingRules(proxySettings, [], false, false, true);
    let fakeOutbound = buildXrayVLESSOutbound('fake-outbound', 'google.com', '443', userID, 'google.com', 'google.com', '', true, false, userID, defaultHttpsPorts);
    delete fakeOutbound.streamSettings.sockopt;
    fakeOutbound.streamSettings.wsSettings.path = '/';
    config.outbounds.push(fakeOutbound);

    return config;
}

export async function getXrayCustomConfigs(env, proxySettings, hostName, isFragment, userID, trojanPassword, dohURL, defaultHttpsPorts) {
    let configs = [];
    let outbounds = [];
    let protocols = [];
    let chainProxy;
    const {
        proxyIP,
        outProxy,
        outProxyParams,
        cleanIPs,
        enableIPv6,
        customCdnAddrs,
        customCdnHost,
        customCdnSni,
        vlessConfigs,
        trojanConfigs,
        ports
    } = proxySettings;

    if (outProxy) {
        const proxyParams = JSON.parse(outProxyParams);
        try {
            chainProxy = buildXrayChainOutbound(proxyParams);
        } catch (error) {
            console.log('An error occured while parsing chain proxy: ', error);
            chainProxy = undefined;
            await env.bpb.put("proxySettings", JSON.stringify({
                ...proxySettings,
                outProxy: '',
                outProxyParams: ''
            }));
        }
    }

    const Addresses = await getConfigAddresses(hostName, cleanIPs, enableIPv6, dohURL);
    const customCdnAddresses = customCdnAddrs ? customCdnAddrs.split(',') : [];
    const totalAddresses = isFragment ? [...Addresses] : [...Addresses, ...customCdnAddresses];
    const totalPorts = ports.filter(port => isFragment ? defaultHttpsPorts.includes(port): true);
    vlessConfigs && protocols.push('VLESS');
    trojanConfigs && protocols.push('Trojan');
    let proxyIndex = 1;

    for (const protocol of protocols) {
        let protocolIndex = 1;
        for (const port of totalPorts)  {
            for (const addr of totalAddresses) {
                const isCustomAddr = customCdnAddresses.includes(addr);
                const configType = isCustomAddr ? 'C' : isFragment ? 'F' : '';
                const sni = isCustomAddr ? customCdnSni : randomUpperCase(hostName);
                const host = isCustomAddr ? customCdnHost : hostName;
                const remark = generateRemark(protocolIndex, port, addr, cleanIPs, protocol, configType);
                let customConfig = buildXrayConfig(proxySettings, remark, isFragment, false, chainProxy, undefined, false);
                customConfig.dns = await buildXrayDNS(proxySettings, [addr], undefined, false, false, dohURL);
                customConfig.routing.rules = buildXrayRoutingRules(proxySettings, [addr], chainProxy, false, false);
                let outbound = protocol === 'VLESS'
                    ? buildXrayVLESSOutbound('proxy', addr, port, host, sni, proxyIP, isFragment, isCustomAddr, userID, defaultHttpsPorts)
                    : buildXrayTrojanOutbound('proxy', addr, port, host, sni, proxyIP, isFragment, isCustomAddr, trojanPassword, defaultHttpsPorts);

                customConfig.outbounds.unshift({...outbound});
                outbound.tag = `prox-${proxyIndex}`;

                if (chainProxy) {
                    customConfig.outbounds.unshift(chainProxy);
                    let chainOutbound = structuredClone(chainProxy);
                    chainOutbound.tag = `chain-${proxyIndex}`;
                    chainOutbound.streamSettings.sockopt.dialerProxy = `prox-${proxyIndex}`;
                    outbounds.push(chainOutbound);
                }

                outbounds.push(outbound);
                configs.push(customConfig);
                proxyIndex++;
                protocolIndex++;
            }
        }
    }

    const bestPing = await buildXrayBestPingConfig(proxySettings, totalAddresses, chainProxy, outbounds, isFragment, dohURL);
    if (!isFragment) return [...configs, bestPing];
    const bestFragment = await buildXrayBestFragmentConfig(proxySettings, hostName, chainProxy, outbounds, dohURL);
    const workerLessConfig = await buildXrayWorkerLessConfig(proxySettings, userID, dohURL, defaultHttpsPorts);
    configs.push(bestPing, bestFragment, workerLessConfig);

    return configs;
}

export async function getXrayWarpConfigs (proxySettings, warpConfigs, client, dohURL) {
    let xrayWarpConfigs = [];
    let xrayWoWConfigs = [];
    let xrayWarpOutbounds = [];
    let xrayWoWOutbounds = [];
    const { warpEndpoints } = proxySettings;
    const outboundDomains = warpEndpoints.split(',').map(endpoint => endpoint.split(':')[0]).filter(address => isDomain(address));
    const proIndicator = client === 'nikang' ? ' Pro ' : ' ';

    for (const [index, endpoint] of warpEndpoints.split(',').entries()) {
        const endpointHost = endpoint.split(':')[0];
        let warpConfig = buildXrayConfig(proxySettings, `💦 ${index + 1} - Warp${proIndicator}🇮🇷`, false, false, false, undefined, true);
        let WoWConfig = buildXrayConfig(proxySettings, `💦 ${index + 1} - WoW${proIndicator}🌍`, false, false, true, undefined, true);
        warpConfig.dns = WoWConfig.dns = await buildXrayDNS(proxySettings, [endpointHost], undefined, false, true, dohURL);
        warpConfig.routing.rules = buildXrayRoutingRules(proxySettings, [endpointHost], false, false, false);
        WoWConfig.routing.rules = buildXrayRoutingRules(proxySettings, [endpointHost], true, false, false);
        const warpOutbound = buildXrayWarpOutbound(proxySettings, warpConfigs, endpoint, false, client);
        const WoWOutbound = buildXrayWarpOutbound(proxySettings, warpConfigs, endpoint, true, client);
        warpOutbound.settings.peers[0].endpoint = endpoint;
        WoWOutbound.settings.peers[0].endpoint = endpoint;
        warpConfig.outbounds.unshift(warpOutbound);
        WoWConfig.outbounds.unshift(WoWOutbound, warpOutbound);
        xrayWarpConfigs.push(warpConfig);
        xrayWoWConfigs.push(WoWConfig);
        const proxyOutbound = structuredClone(warpOutbound);
        proxyOutbound.tag = `prox-${index + 1}`;
        const chainOutbound = structuredClone(WoWOutbound);
        chainOutbound.tag = `chain-${index + 1}`;
        chainOutbound.streamSettings.sockopt.dialerProxy = `prox-${index + 1}`;
        xrayWarpOutbounds.push(proxyOutbound);
        xrayWoWOutbounds.push(chainOutbound);
    }

    const dnsObject = await buildXrayDNS(proxySettings, outboundDomains, undefined, false, true, dohURL);
    let xrayWarpBestPing = buildXrayConfig(proxySettings, `💦 Warp${proIndicator}- Best Ping 🚀`, false, true, false, undefined, true);
    xrayWarpBestPing.dns = dnsObject;
    xrayWarpBestPing.routing.rules = buildXrayRoutingRules(proxySettings, outboundDomains, false, true, false);
    xrayWarpBestPing.outbounds.unshift(...xrayWarpOutbounds);
    let xrayWoWBestPing = buildXrayConfig(proxySettings, `💦 WoW${proIndicator}- Best Ping 🚀`, false, true, true, undefined, true);
    xrayWoWBestPing.dns = dnsObject;
    xrayWoWBestPing.routing.rules = buildXrayRoutingRules(proxySettings, outboundDomains, true, true, false);
    xrayWoWBestPing.outbounds.unshift(...xrayWoWOutbounds, ...xrayWarpOutbounds);
    return [...xrayWarpConfigs, ...xrayWoWConfigs, xrayWarpBestPing, xrayWoWBestPing];
}

async function buildClashDNS (proxySettings, isWarp) {
    const {
        remoteDNS,
        resolvedRemoteDNS,
        localDNS,
        vlessTrojanFakeDNS,
        warpFakeDNS,
        bypassLAN,
        bypassIran,
        bypassChina,
        bypassRussia
    } = proxySettings;

    const finalRemoteDNS = isWarp
        ? ['1.1.1.1', '1.0.0.1']
        : [remoteDNS];
    let clashLocalDNS = localDNS === 'localhost' ? 'system' : localDNS;
    const isFakeDNS = (vlessTrojanFakeDNS && !isWarp) || (warpFakeDNS && isWarp);

    let dns = {
        "enable": true,
        "listen": "0.0.0.0:1053",
        "ipv6": true,
        "respect-rules": true,
        "nameserver": finalRemoteDNS,
        "proxy-server-nameserver": [clashLocalDNS]
    };

    if (resolvedRemoteDNS.server && !isWarp) {
        dns['hosts'] = {
            [resolvedRemoteDNS.server]: resolvedRemoteDNS.staticIPs
        };
    }

    let geosites = [];
    bypassLAN && geosites.push('private');
    bypassIran && geosites.push('category-ir');
    bypassChina && geosites.push('cn');
    bypassRussia && geosites.push('category-ru');

    if (bypassIran || bypassChina || bypassLAN || bypassRussia) {
        dns['nameserver-policy'] = {
            [`geosite:${geosites.join(',')}`]: [clashLocalDNS],
            'www.gstatic.com': [clashLocalDNS]
        };
    }

    if (isFakeDNS) {
        dns["enhanced-mode"] = "fake-ip";
        dns["fake-ip-range"] = "198.18.0.1/16";
    }

    return dns;
}

function buildClashRoutingRules (proxySettings) {
    let rules = [];
    const {
        localDNS,
        bypassLAN,
        bypassIran,
        bypassChina,
        bypassRussia,
        blockAds,
        blockPorn,
        blockUDP443
    } = proxySettings;

    localDNS !== 'localhost' && rules.push(`AND,((IP-CIDR,${localDNS}/32),(DST-PORT,53)),DIRECT`);
    bypassLAN && rules.push('GEOSITE,private,DIRECT');
    bypassIran && rules.push('GEOSITE,category-ir,DIRECT');
    bypassChina && rules.push('GEOSITE,cn,DIRECT');
    bypassRussia && rules.push('GEOSITE,category-ru,DIRECT');
    bypassLAN && rules.push('GEOIP,private,DIRECT,no-resolve');
    bypassIran && rules.push('GEOIP,ir,DIRECT,no-resolve');
    bypassChina && rules.push('GEOIP,cn,DIRECT,no-resolve');
    bypassRussia && rules.push('GEOIP,ru,DIRECT,no-resolve');
    blockUDP443 && rules.push('AND,((NETWORK,udp),(DST-PORT,443)),REJECT');
    blockAds && rules.push('GEOSITE,category-ads-all,REJECT', 'GEOSITE,category-ads-ir,REJECT');
    blockPorn && rules.push('GEOSITE,category-porn,REJECT');
    rules.push('MATCH,✅ Selector');

    return rules;
}

function buildClashVLESSOutbound (remark, address, port, host, sni, path, allowInsecure, userID, defaultHttpsPorts) {
    const tls = defaultHttpsPorts.includes(port) ? true : false;
    const addr = isIPv6(address) ? address.replace(/\[|\]/g, '') : address;
    let outbound = {
        "name": remark,
        "type": "vless",
        "server": addr,
        "port": +port,
        "uuid": userID,
        "tls": tls,
        "network": "ws",
        "udp": false,
        "ws-opts": {
            "path": path,
            "headers": { "host": host },
            "max-early-data": 2560,
            "early-data-header-name": "Sec-WebSocket-Protocol"
        }
    };

    if (tls) {
        Object.assign(outbound, {
            "servername": sni,
            "alpn": ["h2", "http/1.1"],
            "client-fingerprint": "random",
            "skip-cert-verify": allowInsecure
        });
    }

    return outbound;
}

function buildClashTrojanOutbound (remark, address, port, host, sni, path, allowInsecure, trojanPassword, defaultHttpsPorts) {
    const addr = isIPv6(address) ? address.replace(/\[|\]/g, '') : address;
    return {
        "name": remark,
        "type": "trojan",
        "server": addr,
        "port": +port,
        "password": trojanPassword,
        "network": "ws",
        "udp": false,
        "ws-opts": {
            "path": path,
            "headers": { "host": host },
            "max-early-data": 2560,
            "early-data-header-name": "Sec-WebSocket-Protocol"
        },
        "sni": sni,
        "alpn": ["h2", "http/1.1"],
        "client-fingerprint": "random",
        "skip-cert-verify": allowInsecure
    };
}

function buildClashWarpOutbound (warpConfigs, remark, endpoint, chain) {
    const ipv6Regex = /\[(.*?)\]/;
    const portRegex = /[^:]*$/;
    const endpointServer = endpoint.includes('[') ? endpoint.match(ipv6Regex)[1] : endpoint.split(':')[0];
    const endpointPort = endpoint.includes('[') ? +endpoint.match(portRegex)[0] : +endpoint.split(':')[1];
    const {
        warpIPv6,
        reserved,
        publicKey,
        privateKey
    } = extractWireguardParams(warpConfigs, chain);

    return {
        "name": remark,
        "type": "wireguard",
        "ip": "172.16.0.2/32",
        "ipv6": warpIPv6,
        "private-key": privateKey,
        "server": endpointServer,
        "port": endpointPort,
        "public-key": publicKey,
        "allowed-ips": ["0.0.0.0/0", "::/0"],
        "reserved": reserved,
        "udp": true,
        "mtu": 1280,
        "dialer-proxy": chain,
        "remote-dns-resolve": true,
        "dns": [ "1.1.1.1", "1.0.0.1" ]
    };
}

function buildClashChainOutbound(chainProxyParams) {
    if (["socks", "http"].includes(chainProxyParams.protocol)) {
        const { protocol, host, port, user, pass } = chainProxyParams;
        const proxyType = protocol === 'socks' ? 'socks5' : protocol;
        return {
            "name": "",
            "type": proxyType,
            "server": host,
            "port": +port,
            "dialer-proxy": "",
            "username": user,
            "password": pass
        };
    }

    const { hostName, port, uuid, flow, security, type, sni, fp, alpn, pbk, sid, headerType, host, path, serviceName } = chainProxyParams;
    let chainOutbound = {
        "name": "💦 Chain Best Ping 💥",
        "type": "vless",
        "server": hostName,
        "port": +port,
        "udp": true,
        "uuid": uuid,
        "flow": flow,
        "network": type,
        "dialer-proxy": "💦 Best Ping 💥"
    };

    if (security === 'tls') {
        const tlsAlpns = alpn ? alpn?.split(',') : [];
        Object.assign(chainOutbound, {
            "tls": true,
            "servername": sni,
            "alpn": tlsAlpns,
            "client-fingerprint": fp
        });
    }

    if (security === 'reality') Object.assign(chainOutbound, {
        "tls": true,
        "servername": sni,
        "client-fingerprint": fp,
        "reality-opts": {
            "public-key": pbk,
            "short-id": sid
        }
    });

    if (headerType === 'http') {
        const httpPaths = path?.split(',');
        chainOutbound["http-opts"] = {
            "method": "GET",
            "path": httpPaths,
            "headers": {
                "Connection": ["keep-alive"],
                "Content-Type": ["application/octet-stream"]
            }
        };
    }

    if (type === 'ws') {
        const wsPath = path?.split('?ed=')[0];
        const earlyData = +path?.split('?ed=')[1];
        chainOutbound["ws-opts"] = {
            "path": wsPath,
            "headers": {
                "Host": host
            },
            "max-early-data": earlyData,
            "early-data-header-name": "Sec-WebSocket-Protocol"
        };
    }

    if (type === 'grpc') chainOutbound["grpc-opts"] = {
        "grpc-service-name": serviceName
    };

    return chainOutbound;
}

export async function getClashWarpConfig(proxySettings, warpConfigs) {
    const { warpEndpoints } = proxySettings;
    let config = structuredClone(clashConfigTemp);
    config.dns = await buildClashDNS(proxySettings, true);
    config.rules = buildClashRoutingRules(proxySettings);
    const selector = config['proxy-groups'][0];
    const warpUrlTest = config['proxy-groups'][1];
    selector.proxies = ['💦 Warp - Best Ping 🚀', '💦 WoW - Best Ping 🚀'];
    warpUrlTest.name = '💦 Warp - Best Ping 🚀';
    warpUrlTest.interval = +proxySettings.bestWarpInterval;
    config['proxy-groups'].push(structuredClone(warpUrlTest));
    const WoWUrlTest = config['proxy-groups'][2];
    WoWUrlTest.name = '💦 WoW - Best Ping 🚀';
    let warpRemarks = [], WoWRemarks = [];

    warpEndpoints.split(',').forEach( (endpoint, index) => {
        const warpRemark = `💦 ${index + 1} - Warp 🇮🇷`;
        const WoWRemark = `💦 ${index + 1} - WoW 🌍`;
        const warpOutbound = buildClashWarpOutbound(warpConfigs, warpRemark, endpoint, '');
        const WoWOutbound = buildClashWarpOutbound(warpConfigs, WoWRemark, endpoint, warpRemark);
        config.proxies.push(WoWOutbound, warpOutbound);
        warpRemarks.push(warpRemark);
        WoWRemarks.push(WoWRemark);
        warpUrlTest.proxies.push(warpRemark);
        WoWUrlTest.proxies.push(WoWRemark);
    });

    selector.proxies.push(...warpRemarks, ...WoWRemarks);
    return config;
}

export async function getClashNormalConfig (env, proxySettings, hostName, userID, trojanPassword, dohURL, defaultHttpsPorts) {
    let chainProxy;
    const {
        cleanIPs,
        proxyIP,
        ports,
        vlessConfigs,
        trojanConfigs,
        outProxy,
        outProxyParams,
        customCdnAddrs,
        customCdnHost,
        customCdnSni,
        bestVLESSTrojanInterval,
        enableIPv6
    } = proxySettings;

    if (outProxy) {
        const proxyParams = JSON.parse(outProxyParams);
        try {
            chainProxy = buildClashChainOutbound(proxyParams);
        } catch (error) {
            console.log('An error occured while parsing chain proxy: ', error);
            chainProxy = undefined;
            await env.bpb.put("proxySettings", JSON.stringify({
                ...proxySettings,
                outProxy: '',
                outProxyParams: ''
            }));
        }
    }

    let config = structuredClone(clashConfigTemp);
    config.dns = await buildClashDNS(proxySettings, false);
    config.rules = buildClashRoutingRules(proxySettings);
    const selector = config['proxy-groups'][0];
    const urlTest = config['proxy-groups'][1];
    selector.proxies = ['💦 Best Ping 💥'];
    urlTest.name = '💦 Best Ping 💥';
    urlTest.interval = +bestVLESSTrojanInterval;
    const Addresses = await getConfigAddresses(hostName, cleanIPs, enableIPv6, dohURL);
    const customCdnAddresses = customCdnAddrs ? customCdnAddrs.split(',') : [];
    const totalAddresses = [...Addresses, ...customCdnAddresses];
    let proxyIndex = 1, path;
    const protocols = [
        ...(vlessConfigs ? ['VLESS'] : []),
        ...(trojanConfigs ? ['Trojan'] : [])
    ];

    protocols.forEach ( protocol => {
        let protocolIndex = 1;
        ports.forEach ( port => {
            totalAddresses.forEach( addr => {
                let VLESSOutbound, TrojanOutbound;
                const isCustomAddr = customCdnAddresses.includes(addr);
                const configType = isCustomAddr ? 'C' : '';
                const sni = isCustomAddr ? customCdnSni : randomUpperCase(hostName);
                const host = isCustomAddr ? customCdnHost : hostName;
                const remark = generateRemark(protocolIndex, port, addr, cleanIPs, protocol, configType).replace(' : ', ' - ');

                if (protocol === 'VLESS') {
                    path = `/${getRandomPath(16)}${proxyIP ? `/${btoa(proxyIP)}` : ''}`;
                    VLESSOutbound = buildClashVLESSOutbound(
                        chainProxy ? `proxy-${proxyIndex}` : remark,
                        addr,
                        port,
                        host,
                        sni,
                        path,
                        isCustomAddr,
                        userID,
                        defaultHttpsPorts
                    );
                    config.proxies.push(VLESSOutbound);
                    selector.proxies.push(remark);
                    urlTest.proxies.push(remark);
                }

                if (protocol === 'Trojan' && defaultHttpsPorts.includes(port)) {
                    path = `/tr${getRandomPath(16)}${proxyIP ? `/${btoa(proxyIP)}` : ''}`;
                    TrojanOutbound = buildClashTrojanOutbound(
                        chainProxy ? `proxy-${proxyIndex}` : remark,
                        addr,
                        port,
                        host,
                        sni,
                        path,
                        isCustomAddr,
                        trojanPassword,
                        defaultHttpsPorts
                    );
                    config.proxies.push(TrojanOutbound);
                    selector.proxies.push(remark);
                    urlTest.proxies.push(remark);
                }

                if (chainProxy) {
                    let chain = structuredClone(chainProxy);
                    chain['name'] = remark;
                    chain['dialer-proxy'] = `proxy-${proxyIndex}`;
                    config.proxies.push(chain);
                }

                proxyIndex++;
                protocolIndex++;
            });
        });
    });

    return config;
}

function buildSingBoxDNS (proxySettings, isChain, isWarp) {
    const {
        remoteDNS,
        localDNS,
        vlessTrojanFakeDNS,
        warpFakeDNS,
        bypassIran,
        bypassChina,
        bypassRussia,
        blockAds,
        blockPorn
    } = proxySettings;

    let fakeip;
    const isFakeDNS = (vlessTrojanFakeDNS && !isWarp) || (warpFakeDNS && isWarp);
    const servers = [
        {
            address: isWarp ? '1.1.1.1' : remoteDNS,
            address_resolver: "dns-direct",
            strategy: "prefer_ipv4",
            detour: isChain ? 'proxy-1' : "proxy",
            tag: "dns-remote"
        },
        {
            address: localDNS === 'localhost' ? 'local' : localDNS,
            strategy: "prefer_ipv4",
            detour: "direct",
            tag: "dns-direct"
        },
        {
            address: "rcode://success",
            tag: "dns-block"
        }
    ];

    let rules = [
        {
            outbound: "any",
            server: "dns-direct"
        }
    ];

    if (bypassIran || bypassChina || bypassRussia) {
        let bypassRules = {
            rule_set: [],
            server: "dns-direct"
        };
        bypassIran && bypassRules.rule_set.push("geosite-ir");
        bypassChina && bypassRules.rule_set.push("geosite-cn");
        bypassRussia && bypassRules.rule_set.push("geosite-category-ru");
        rules.push(bypassRules);
    }

    let blockRules = {
        disable_cache: true,
        rule_set: [
            "geosite-malware",
            "geosite-phishing",
            "geosite-cryptominers"
        ],
        server: "dns-block"
    };

    blockAds && blockRules.rule_set.push("geosite-category-ads-all");
    blockPorn && blockRules.rule_set.push("geosite-nsfw");
    rules.push(blockRules);

    if (isFakeDNS) {
        servers.push({
            address: "fakeip",
            tag: "dns-fake"
        });

        rules.push({
            disable_cache: true,
            inbound: "tun-in",
            query_type: [
              "A",
              "AAAA"
            ],
            server: "dns-fake"
        });

        fakeip = {
            enabled: true,
            inet4_range: "198.18.0.0/15",
            inet6_range: "fc00::/18"
        };
    }

    return {servers, rules, fakeip};
}

function buildSingBoxRoutingRules (proxySettings) {
    const {
        bypassLAN,
        bypassIran,
        bypassChina,
        bypassRussia,
        blockAds,
        blockPorn,
        blockUDP443
    } = proxySettings;

    let rules = [
        {
            inbound: "dns-in",
            outbound: "dns-out"
        },
        {
            network: "udp",
            port: 53,
            outbound: "dns-out"
        }
    ];

    let ruleSet = [
        {
            type: "remote",
            tag: "geosite-malware",
            format: "binary",
            url: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-malware.srs",
            download_detour: "direct"
        },
        {
            type: "remote",
            tag: "geosite-phishing",
            format: "binary",
            url: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-phishing.srs",
            download_detour: "direct"
        },
        {
            type: "remote",
            tag: "geosite-cryptominers",
            format: "binary",
            url: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-cryptominers.srs",
            download_detour: "direct"
        },
        {
            type: "remote",
            tag: "geoip-malware",
            format: "binary",
            url: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-malware.srs",
            download_detour: "direct"
        },
        {
            type: "remote",
            tag: "geoip-phishing",
            format: "binary",
            url: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-phishing.srs",
            download_detour: "direct"
        }
    ];

    if (bypassIran) {
        rules.push({
            rule_set: ["geosite-ir", "geoip-ir"],
            outbound: "direct"
        });

        ruleSet.push({
            type: "remote",
            tag: "geosite-ir",
            format: "binary",
            url: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-ir.srs",
            download_detour: "direct"
        },
        {
            type: "remote",
            tag: "geoip-ir",
            format: "binary",
            url: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ir.srs",
            download_detour: "direct"
        });
    }

    if (bypassChina) {
        rules.push({
            rule_set: ["geosite-cn", "geoip-cn"],
            outbound: "direct"
        });

        ruleSet.push({
            type: "remote",
            tag: "geosite-cn",
            format: "binary",
            url: "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
            download_detour: "direct"
        },
        {
            type: "remote",
            tag: "geoip-cn",
            format: "binary",
            url: "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
            download_detour: "direct"
        });
    }

    if (bypassRussia) {
        rules.push({
            rule_set: ["geosite-category-ru", "geoip-ru"],
            outbound: "direct"
        });

        ruleSet.push({
            type: "remote",
            tag: "geosite-category-ru",
            format: "binary",
            url: "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ru.srs",
            download_detour: "direct"
        },
        {
            type: "remote",
            tag: "geoip-ru",
            format: "binary",
            url: "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs",
            download_detour: "direct"
        });
    }

    bypassLAN && rules.push({
        ip_is_private: true,
        outbound: "direct"
    });

    blockUDP443 && rules.push({
        network: "udp",
        port: 443,
        protocol: "quic",
        outbound: "block"
    });

    let blockRuleSet = {
        rule_set: [
            "geosite-malware",
            "geosite-phishing",
            "geosite-cryptominers",
            "geoip-malware",
            "geoip-phishing"
        ],
        outbound: "block"
    };

    if (blockAds) {
        blockRuleSet.rule_set.push("geosite-category-ads-all");
        ruleSet.push({
            type: "remote",
            tag: "geosite-category-ads-all",
            format: "binary",
            url: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-category-ads-all.srs",
            download_detour: "direct"
        });
    }

    if (blockPorn) {
        blockRuleSet.rule_set.push("geosite-nsfw");
        ruleSet.push({
            type: "remote",
            tag: "geosite-nsfw",
            format: "binary",
            url: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-nsfw.srs",
            download_detour: "direct"
        });
    }

    rules.push(blockRuleSet);
    rules.push({
        ip_cidr: ["224.0.0.0/3", "ff00::/8"],
        source_ip_cidr: ["224.0.0.0/3", "ff00::/8"],
        outbound: "block"
    });

    return {rules: rules, rule_set: ruleSet};
}

function buildSingBoxVLESSOutbound (proxySettings, remark, address, port, host, sni, allowInsecure, isFragment, userID, defaultHttpsPorts) {
    const { lengthMin, lengthMax, intervalMin, intervalMax, proxyIP } = proxySettings;
    const path = `/${getRandomPath(16)}${proxyIP ? `/${btoa(proxyIP)}` : ''}`;
    const tls = defaultHttpsPorts.includes(port) ? true : false;
    let outbound =  {
        type: "vless",
        server: address,
        server_port: +port,
        uuid: userID,
        tls: {
            alpn: "http/1.1",
            enabled: true,
            insecure: allowInsecure,
            server_name: sni,
            utls: {
                enabled: true,
                fingerprint: "randomized"
            }
        },
        transport: {
            early_data_header_name: "Sec-WebSocket-Protocol",
            max_early_data: 2560,
            headers: {
                Host: host
            },
            path: path,
            type: "ws"
        },
        tag: remark
    };

    if (!tls) delete outbound.tls;
    if (isFragment) outbound.tls_fragment = {
        enabled: true,
        size: `${lengthMin}-${lengthMax}`,
        sleep: `${intervalMin}-${intervalMax}`
    };

    return outbound;
}

function buildSingBoxTrojanOutbound (proxySettings, remark, address, port, host, sni, allowInsecure, isFragment, trojanPassword, defaultHttpsPorts) {
    const { lengthMin, lengthMax, intervalMin, intervalMax, proxyIP } = proxySettings;
    const path = `/tr${getRandomPath(16)}${proxyIP ? `/${btoa(proxyIP)}` : ''}`;
    const tls = defaultHttpsPorts.includes(port) ? true : false;
    let outbound = {
        type: "trojan",
        password: trojanPassword,
        server: address,
        server_port: +port,
        tls: {
            alpn: "http/1.1",
            enabled: true,
            insecure: allowInsecure,
            server_name: sni,
            utls: {
                enabled: true,
                fingerprint: "randomized"
            }
        },
        transport: {
            early_data_header_name: "Sec-WebSocket-Protocol",
            max_early_data: 2560,
            headers: {
                Host: host
            },
            path: path,
            type: "ws"
        },
        tag: remark
    }

    if (!tls) delete outbound.tls;
    if (isFragment) outbound.tls_fragment = {
        enabled: true,
        size: `${lengthMin}-${lengthMax}`,
        sleep: `${intervalMin}-${intervalMax}`
    };

    return outbound;
}

function buildSingBoxWarpOutbound (proxySettings, warpConfigs, remark, endpoint, chain, client) {
    const ipv6Regex = /\[(.*?)\]/;
    const portRegex = /[^:]*$/;
    const endpointServer = endpoint.includes('[') ? endpoint.match(ipv6Regex)[1] : endpoint.split(':')[0];
    const endpointPort = endpoint.includes('[') ? +endpoint.match(portRegex)[0] : +endpoint.split(':')[1];
    const {
		hiddifyNoiseMode,
		noiseCountMin,
		noiseCountMax,
		noiseSizeMin,
		noiseSizeMax,
		noiseDelayMin,
		noiseDelayMax
	} = proxySettings;

    const {
        warpIPv6,
        reserved,
        publicKey,
        privateKey
    } = extractWireguardParams(warpConfigs, chain);

    let outbound = {
        local_address: [
            "172.16.0.2/32",
            warpIPv6
        ],
        mtu: 1280,
        peer_public_key: publicKey,
        private_key: privateKey,
        reserved: reserved,
        server: endpointServer,
        server_port: endpointPort,
        type: "wireguard",
        detour: chain,
        tag: remark
    };

    client === 'hiddify' && Object.assign(outbound, {
        fake_packets_mode: hiddifyNoiseMode,
        fake_packets: noiseCountMin === noiseCountMax ? noiseCountMin : `${noiseCountMin}-${noiseCountMax}`,
        fake_packets_size: noiseSizeMin === noiseSizeMax ? noiseSizeMin : `${noiseSizeMin}-${noiseSizeMax}`,
        fake_packets_delay: noiseDelayMin === noiseDelayMax ? noiseDelayMin : `${noiseDelayMin}-${noiseDelayMax}`
    });

    return outbound;
}

function buildSingBoxChainOutbound (chainProxyParams) {
    if (["socks", "http"].includes(chainProxyParams.protocol)) {
        const { protocol, host, port, user, pass } = chainProxyParams;

        let chainOutbound = {
            type: protocol,
            tag: "",
            server: host,
            server_port: +port,
            username: user,
            password: pass,
            detour: ""
        };

        protocol === 'socks' && Object.assign(chainOutbound, {
            version: "5",
            network: "tcp"
        });

        return chainOutbound;
    }

    const { hostName, port, uuid, flow, security, type, sni, fp, alpn, pbk, sid, headerType, host, path, serviceName } = chainProxyParams;
    let chainOutbound = {
        type: "vless",
        tag: "",
        server: hostName,
        server_port: +port,
        uuid: uuid,
        flow: flow,
        network: "tcp",
        detour: ""
    };

    if (security === 'tls' || security === 'reality') {
        const tlsAlpns = alpn ? alpn?.split(',').filter(value => value !== 'h2') : [];
        chainOutbound.tls = {
            enabled: true,
            server_name: sni,
            insecure: false,
            alpn: tlsAlpns,
            utls: {
                enabled: true,
                fingerprint: fp
            }
        };

        if (security === 'reality') {
            chainOutbound.tls.reality = {
                enabled: true,
                public_key: pbk,
                short_id: sid
            };

            delete chainOutbound.tls.alpn;
        }
    }

    if (headerType === 'http') {
        const httpHosts = host?.split(',');
        chainOutbound.transport = {
            type: "http",
            host: httpHosts,
            path: path,
            method: "GET",
            headers: {
                "Connection": ["keep-alive"],
                "Content-Type": ["application/octet-stream"]
            },
        };
    }

    if (type === 'ws') {
        const wsPath = path?.split('?ed=')[0];
        const earlyData = +path?.split('?ed=')[1] || 0;
        chainOutbound.transport = {
            type: "ws",
            path: wsPath,
            headers: { Host: host },
            max_early_data: earlyData,
            early_data_header_name: "Sec-WebSocket-Protocol"
        };
    }

    if (type === 'grpc') chainOutbound.transport = {
        type: "grpc",
        service_name: serviceName
    };

    return chainOutbound;
}

export async function getSingBoxWarpConfig (proxySettings, warpConfigs, client) {
    const { warpEndpoints } = proxySettings;
    let config = structuredClone(singboxConfigTemp);
    const dnsObject = buildSingBoxDNS(proxySettings, false, true);
    const {rules, rule_set} = buildSingBoxRoutingRules(proxySettings);
    config.dns.servers = dnsObject.servers;
    config.dns.rules = dnsObject.rules;
    if (dnsObject.fakeip) config.dns.fakeip = dnsObject.fakeip;
    config.route.rules = rules;
    config.route.rule_set = rule_set;
    const selector = config.outbounds[0];
    const warpUrlTest = config.outbounds[1];
    const proIndicator = client === 'hiddify' ? ' Pro ' : ' ';
    selector.outbounds = [`💦 Warp${proIndicator}- Best Ping 🚀`, `💦 WoW${proIndicator}- Best Ping 🚀`];
    config.outbounds.splice(2, 0, structuredClone(warpUrlTest));
    const WoWUrlTest = config.outbounds[2];
    warpUrlTest.tag = `💦 Warp${proIndicator}- Best Ping 🚀`;
    warpUrlTest.interval = `${proxySettings.bestWarpInterval}s`;
    WoWUrlTest.tag = `💦 WoW${proIndicator}- Best Ping 🚀`;
    WoWUrlTest.interval = `${proxySettings.bestWarpInterval}s`;
    let warpRemarks = [], WoWRemarks = [];

    warpEndpoints.split(',').forEach( (endpoint, index) => {
        const warpRemark = `💦 ${index + 1} - Warp 🇮🇷`;
        const WoWRemark = `💦 ${index + 1} - WoW 🌍`;
        const warpOutbound = buildSingBoxWarpOutbound(proxySettings, warpConfigs, warpRemark, endpoint, '', client);
        const WoWOutbound = buildSingBoxWarpOutbound(proxySettings, warpConfigs, WoWRemark, endpoint, warpRemark, client);
        config.outbounds.push(WoWOutbound, warpOutbound);
        warpRemarks.push(warpRemark);
        WoWRemarks.push(WoWRemark);
        warpUrlTest.outbounds.push(warpRemark);
        WoWUrlTest.outbounds.push(WoWRemark);
    });

    selector.outbounds.push(...warpRemarks, ...WoWRemarks);
    return config;
}

export async function getSingBoxCustomConfig(env, proxySettings, hostName, client, isFragment, userID, trojanPassword, dohURL, defaultHttpsPorts) {
    let chainProxyOutbound;
    const {
        cleanIPs,
        ports,
        vlessConfigs,
        trojanConfigs,
        outProxy,
        outProxyParams,
        customCdnAddrs,
        customCdnHost,
        customCdnSni,
        bestVLESSTrojanInterval,
        enableIPv6
    } = proxySettings;

    if (outProxy) {
        const proxyParams = JSON.parse(outProxyParams);
        try {
            chainProxyOutbound = buildSingBoxChainOutbound(proxyParams);
        } catch (error) {
            console.log('An error occured while parsing chain proxy: ', error);
            chainProxyOutbound = undefined;
            await env.bpb.put("proxySettings", JSON.stringify({
                ...proxySettings,
                outProxy: '',
                outProxyParams: ''
            }));
            throw new Error(error);
        }
    }

    let config = structuredClone(singboxConfigTemp);
    const dnsObject = buildSingBoxDNS(proxySettings, chainProxyOutbound, false);
    const {rules, rule_set} = buildSingBoxRoutingRules(proxySettings);
    config.dns.servers = dnsObject.servers;
    config.dns.rules = dnsObject.rules;
    if (dnsObject.fakeip) config.dns.fakeip = dnsObject.fakeip;
    config.route.rules = rules;
    config.route.rule_set = rule_set;
    const selector = config.outbounds[0];
    const urlTest = config.outbounds[1];
    selector.outbounds = ['💦 Best Ping 💥'];
    urlTest.interval = `${bestVLESSTrojanInterval}s`;
    urlTest.tag = '💦 Best Ping 💥';
    const Addresses = await getConfigAddresses(hostName, cleanIPs, enableIPv6, dohURL);
    const customCdnAddresses = customCdnAddrs ? customCdnAddrs.split(',') : [];
    const totalAddresses = [...Addresses, ...customCdnAddresses];
    const totalPorts = ports.filter(port => isFragment ? defaultHttpsPorts.includes(port) : true);
    let proxyIndex = 1;
    const protocols = [
        ...(vlessConfigs ? ['VLESS'] : []),
        ...(trojanConfigs ? ['Trojan'] : [])
    ];

    protocols.forEach ( protocol => {
        let protocolIndex = 1;
        totalPorts.forEach ( port => {
            totalAddresses.forEach ( addr => {
                let VLESSOutbound, TrojanOutbound;
                const isCustomAddr = customCdnAddresses.includes(addr);
                const configType = isCustomAddr ? 'C' : isFragment ? 'F' : '';
                const sni = isCustomAddr ? customCdnSni : randomUpperCase(hostName);
                const host = isCustomAddr ? customCdnHost : hostName;
                const remark = generateRemark(protocolIndex, port, addr, cleanIPs, protocol, configType);

                if (protocol === 'VLESS') {
                    VLESSOutbound = buildSingBoxVLESSOutbound (
                        proxySettings,
                        chainProxyOutbound ? `proxy-${proxyIndex}` : remark,
                        addr,
                        port,
                        host,
                        sni,
                        isCustomAddr,
                        isFragment,
                        userID,
                        defaultHttpsPorts
                    );
                    config.outbounds.push(VLESSOutbound);
                }

                if (protocol === 'Trojan') {
                    TrojanOutbound = buildSingBoxTrojanOutbound (
                        proxySettings,
                        chainProxyOutbound ? `proxy-${proxyIndex}` : remark,
                        addr,
                        port,
                        host,
                        sni,
                        isCustomAddr,
                        isFragment,
                        trojanPassword,
                        defaultHttpsPorts
                    );
                    config.outbounds.push(TrojanOutbound);
                }

                if (chainProxyOutbound) {
                    let chain = structuredClone(chainProxyOutbound);
                    chain.tag = remark;
                    chain.detour = `proxy-${proxyIndex}`;
                    config.outbounds.push(chain);
                }

                selector.outbounds.push(remark);
                urlTest.outbounds.push(remark);
                proxyIndex++;
                protocolIndex++;
            });
        });
    });

    return config;
}

export async function getNormalConfigs(proxySettings, hostName, client, userID, trojanPassword, dohURL, defaultHttpsPorts) {
    const {
        cleanIPs,
        proxyIP,
        ports,
        vlessConfigs,
        trojanConfigs ,
        outProxy,
        customCdnAddrs,
        customCdnHost,
        customCdnSni,
        enableIPv6
    } = proxySettings;

    let vlessConfs = '', trojanConfs = '', chainProxy = '';
    let proxyIndex = 1;
    const Addresses = await getConfigAddresses(hostName, cleanIPs, enableIPv6, dohURL);
    const customCdnAddresses = customCdnAddrs ? customCdnAddrs.split(',') : [];
    const totalAddresses = [...Addresses, ...customCdnAddresses];
    const alpn = client === 'singbox' ? 'http/1.1' : 'h2,http/1.1';
    const trojanPass = encodeURIComponent(trojanPassword);
    const earlyData = client === 'singbox'
        ? '&eh=Sec-WebSocket-Protocol&ed=2560'
        : encodeURIComponent('?ed=2560');

    ports.forEach(port => {
        totalAddresses.forEach((addr, index) => {
            const isCustomAddr = index > Addresses.length - 1;
            const configType = isCustomAddr ? 'C' : '';
            const sni = isCustomAddr ? customCdnSni : randomUpperCase(hostName);
            const host = isCustomAddr ? customCdnHost : hostName;
            const path = `${getRandomPath(16)}${proxyIP ? `/${encodeURIComponent(btoa(proxyIP))}` : ''}${earlyData}`;
            const vlessRemark = encodeURIComponent(generateRemark(proxyIndex, port, addr, cleanIPs, 'VLESS', configType));
            const trojanRemark = encodeURIComponent(generateRemark(proxyIndex, port, addr, cleanIPs, 'Trojan', configType));
            const tlsFields = defaultHttpsPorts.includes(port)
                ? `&security=tls&sni=${sni}&fp=randomized&alpn=${alpn}`
                : '&security=none';

            if (vlessConfigs) {
                vlessConfs += `${atob('dmxlc3M')}://${userID}@${addr}:${port}?path=/${path}&encryption=none&host=${host}&type=ws${tlsFields}#${vlessRemark}\n`;
            }

            if (trojanConfigs) {
                trojanConfs += `${atob('dHJvamFu')}://${trojanPass}@${addr}:${port}?path=/tr${path}&host=${host}&type=ws${tlsFields}#${trojanRemark}\n`;
            }

            proxyIndex++;
        });
    });

    if (outProxy) {
        let chainRemark = `#${encodeURIComponent('💦 Chain proxy 🔗')}`;
        if (outProxy.startsWith('socks') || outProxy.startsWith('http')) {
            const regex = /^(?:socks|http):\/\/([^@]+)@/;
            const isUserPass = outProxy.match(regex);
            const userPass = isUserPass ? isUserPass[1] : false;
            chainProxy = userPass
                ? outProxy.replace(userPass, btoa(userPass)) + chainRemark
                : outProxy + chainRemark;
        } else {
            chainProxy = outProxy.split('#')[0] + chainRemark;
        }
    }

    return btoa(vlessConfs + trojanConfs + chainProxy);
}
