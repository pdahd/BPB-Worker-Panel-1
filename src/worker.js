import { renderHomePage, renderLoginPage, renderErrorPage } from "./utils/html.js";
import { vlessOverWSHandler, trojanOverWSHandler } from "./handlers/websocket.js";
import { getNormalConfigs, getClashNormalConfig, getXrayCustomConfigs, getSingBoxCustomConfig, getClashWarpConfig, getSingBoxWarpConfig, getXrayWarpConfigs } from "./utils/configs.js";
import { isValidUUID } from "./utils/misc.js";
import { connect } from 'cloudflare:sockets';
import nacl from 'tweetnacl';
import sha256 from 'js-sha256';
import { SignJWT, jwtVerify } from 'jose';

// How to generate your own UUID:
// https://www.uuidgenerator.net/
export let userID = '89b3cbba-e6ac-485a-9481-976a0415eab9';
export let trojanPassword = `bpb-trojan`;

// https://www.nslookup.io/domains/bpb.yousef.isegaro.com/dns-records/
const proxyIPs= ['bpb.yousef.isegaro.com'];
export const defaultHttpPorts = ['80', '8080', '2052', '2082', '2086', '2095', '8880'];
export const defaultHttpsPorts = ['443', '8443', '2053', '2083', '2087', '2096'];
let proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
let dohURL = 'https://cloudflare-dns.com/dns-query';
let hashPassword;
let panelVersion = '2.7';

export default {
    /**
     * @param {import("@cloudflare/workers-types").Request} request
     * @param {{UUID: string, PROXYIP: string, DNS_RESOLVER_URL: string}} env
     * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
     * @returns {Promise<Response>}
     */
    async fetch(request, env) {
        try {          
            userID = env.UUID || userID;
            proxyIP = env.PROXYIP || proxyIP;
            dohURL = env.DNS_RESOLVER_URL || dohURL;
            trojanPassword = env.TROJAN_PASS || trojanPassword;
            hashPassword = sha256.sha224(trojanPassword);
            if (!isValidUUID(userID)) throw new Error(`Invalid UUID: ${userID}`);
            const upgradeHeader = request.headers.get('Upgrade');
            const url = new URL(request.url);
            
            if (!upgradeHeader || upgradeHeader !== 'websocket') {
                
                const searchParams = new URLSearchParams(url.search);
                const host = request.headers.get('Host');
                const client = searchParams.get('app');
                const { kvNotFound, proxySettings: settings, warpConfigs } = await getDataset(env);
                if (kvNotFound) {
                    const errorPage = renderErrorPage('KV Dataset is not properly set!', null, true);
                    return new Response(errorPage, { status: 200, headers: {'Content-Type': 'text/html'}});
                } 

                switch (url.pathname) {

                    case '/cf':
                        return new Response(JSON.stringify(request.cf, null, 4), {
                            status: 200,
                            headers: {
                                'Content-Type': 'application/json;charset=utf-8',
                            },
                        });
                        
                    case '/update-warp':
                        const Auth = await Authenticate(request, env); 
                        if (!Auth) return new Response('Unauthorized', { status: 401 });
                        if (request.method === 'POST') {
                            try {
                                const { error: warpPlusError } = await fetchWgConfig(env, settings);
                                if (warpPlusError) {
                                    return new Response(warpPlusError, { status: 400 });
                                } else {
                                    return new Response('Warp configs updated successfully', { status: 200 });
                                }
                            } catch (error) {
                                console.log(error);
                                return new Response(`An error occurred while updating Warp configs! - ${error}`, { status: 500 });
                            }

                        } else {
                            return new Response('Unsupported request', { status: 405 });
                        }

                    case `/sub/${userID}`:
                        try {
                            if (client === 'sfa') {
                                const BestPingSFA = await getSingBoxCustomConfig(env, settings, host, client, false, userID, trojanPassword, dohURL, defaultHttpsPorts);
                                return new Response(JSON.stringify(BestPingSFA, null, 4), {
                                    status: 200,
                                    headers: {
                                        'Content-Type': 'application/json;charset=utf-8',
                                        'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
                                        'CDN-Cache-Control': 'no-store'
                                    }
                                });
                            }

                            if (client === 'clash') {
                                const BestPingClash = await getClashNormalConfig(env, settings, host, userID, trojanPassword, dohURL, defaultHttpsPorts);
                                return new Response(JSON.stringify(BestPingClash, null, 4), {
                                    status: 200,
                                    headers: {
                                        'Content-Type': 'application/json;charset=utf-8',
                                        'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
                                        'CDN-Cache-Control': 'no-store'
                                    }
                                });
                            }

                            if (client === 'xray') {
                                const xrayFullConfigs = await getXrayCustomConfigs(env, settings, host, false, userID, trojanPassword, dohURL, defaultHttpsPorts);
                                return new Response(JSON.stringify(xrayFullConfigs, null, 4), {
                                    status: 200,
                                    headers: {
                                        'Content-Type': 'application/json;charset=utf-8',
                                        'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
                                        'CDN-Cache-Control': 'no-store'
                                    }
                                });
                            }

                            const normalConfigs = await getNormalConfigs(settings, host, client, userID, trojanPassword, dohURL, defaultHttpsPorts);
                            return new Response(normalConfigs, {
                                status: 200,
                                headers: {
                                    'Content-Type': 'text/plain;charset=utf-8',
                                    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
                                    'CDN-Cache-Control': 'no-store'
                                }
                            });
                        } catch (err) {
                            return new Response(JSON.stringify({ error: 'Failed to generate subscription', details: err.message }), {
                                status: 500,
                                headers: { 'Content-Type': 'application/json' }
                            });
                        }

                    case `/fragsub/${userID}`:
                        try {
                            let fragConfigs = client === 'hiddify'
                                ? await getSingBoxCustomConfig(env, settings, host, client, true, userID, trojanPassword, dohURL, defaultHttpsPorts)
                                : await getXrayCustomConfigs(env, settings, host, true, userID, trojanPassword, dohURL, defaultHttpsPorts);

                            return new Response(JSON.stringify(fragConfigs, null, 4), {
                                status: 200,
                                headers: {
                                    'Content-Type': 'application/json;charset=utf-8',
                                    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
                                    'CDN-Cache-Control': 'no-store'
                                }
                            });
                        } catch (err) {
                            return new Response(JSON.stringify({ error: 'Failed to generate subscription', details: err.message }), {
                                status: 500,
                                headers: { 'Content-Type': 'application/json' }
                            });
                        }

                    case `/warpsub/${userID}`:
                        try {
                            if (client === 'clash') {
                                const clashWarpConfig = await getClashWarpConfig(settings, warpConfigs);
                                return new Response(JSON.stringify(clashWarpConfig, null, 4), {
                                    status: 200,
                                    headers: {
                                        'Content-Type': 'application/json;charset=utf-8',
                                        'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
                                        'CDN-Cache-Control': 'no-store'
                                    }
                                });
                            }

                            if (client === 'singbox' || client === 'hiddify') {
                                const singboxWarpConfig = await getSingBoxWarpConfig(settings, warpConfigs, client);
                                return new Response(JSON.stringify(singboxWarpConfig, null, 4), {
                                    status: 200,
                                    headers: {
                                        'Content-Type': 'application/json;charset=utf-8',
                                        'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
                                        'CDN-Cache-Control': 'no-store'
                                    }
                                });
                            }

                            const warpConfig = await getXrayWarpConfigs(settings, warpConfigs, client, dohURL);
                            return new Response(JSON.stringify(warpConfig, null, 4), {
                                status: 200,
                                headers: {
                                    'Content-Type': 'application/json;charset=utf-8',
                                    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
                                    'CDN-Cache-Control': 'no-store'
                                }
                            });
                        } catch (err) {
                            return new Response(JSON.stringify({ error: 'Failed to generate subscription', details: err.message }), {
                                status: 500,
                                headers: { 'Content-Type': 'application/json' }
                            });
                        }

                    case '/panel':
                        const pwd = await env.bpb.get('pwd');
                        const isAuth = await Authenticate(request, env); 
                        if (request.method === 'POST') {     
                            if (!isAuth) return new Response('Unauthorized or expired session!', { status: 401 });
                            const formData = await request.formData();
                            const isReset = formData.get('resetSettings') === 'true';             
                            isReset 
                                ? await updateDataset(env, null, true) 
                                : await updateDataset(env, formData);

                            return new Response('Success', { status: 200 });
                        }
                        
                        if (pwd && !isAuth) return Response.redirect(`${url.origin}/login`, 302);
                        const isPassSet = pwd?.length >= 8;
                        const homePage = renderHomePage(settings, host, isPassSet, panelVersion, defaultHttpPorts, defaultHttpsPorts);
                        return new Response(homePage, {
                            status: 200,
                            headers: {
                                'Content-Type': 'text/html',
                                'Access-Control-Allow-Origin': url.origin,
                                'Access-Control-Allow-Methods': 'GET, POST',
                                'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                                'X-Content-Type-Options': 'nosniff',
                                'X-Frame-Options': 'DENY',
                                'Referrer-Policy': 'strict-origin-when-cross-origin'
                            }
                        });
                                                      
                    case '/login':
                        if (typeof env.bpb !== 'object') {
                            const errorPage = renderErrorPage('KV Dataset is not properly set!', null, true);
                            return new Response(errorPage, { status: 200, headers: {'Content-Type': 'text/html'}});
                        }

                        const loginAuth = await Authenticate(request, env);
                        if (loginAuth) return Response.redirect(`${url.origin}/panel`, 302);
                        let secretKey = env.SECRET_KEY || await env.bpb.get('secretKey');
                        if (!secretKey) {
                            secretKey = generateSecretKey();
                            await env.bpb.put('secretKey', secretKey);
                        }

                        if (request.method === 'POST') {
                            const password = await request.text();
                            const savedPass = await env.bpb.get('pwd');

                            if (password === savedPass) {
                                const jwtToken = await generateJWTToken(secretKey);
                                const cookieHeader = `jwtToken=${jwtToken}; HttpOnly; Secure; Max-Age=${7 * 24 * 60 * 60}; Path=/; SameSite=Strict`;                 
                                return new Response('Success', {
                                    status: 200,
                                    headers: {
                                      'Set-Cookie': cookieHeader,
                                      'Content-Type': 'text/plain',
                                    }
                                });        
                            } else {
                                return new Response('Method Not Allowed', { status: 405 });
                            }
                        }
                        
                        const loginPage = renderLoginPage(panelVersion);
                        return new Response(loginPage, {
                            status: 200,
                            headers: {
                                'Content-Type': 'text/html',
                                'Access-Control-Allow-Origin': url.origin,
                                'Access-Control-Allow-Methods': 'GET, POST',
                                'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                                'X-Content-Type-Options': 'nosniff',
                                'X-Frame-Options': 'DENY',
                                'Referrer-Policy': 'strict-origin-when-cross-origin'
                            }
                        });
                    
                    case '/logout':                        
                        return new Response('Success', {
                            status: 200,
                            headers: {
                                'Set-Cookie': 'jwtToken=; Secure; SameSite=None; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
                                'Content-Type': 'text/plain'
                            }
                        });        

                    case '/panel/password':
                        const oldPwd = await env.bpb.get('pwd');
                        let passAuth = await Authenticate(request, env);
                        if (oldPwd && !passAuth) return new Response('Unauthorized!', { status: 401 });           
                        const newPwd = await request.text();
                        if (newPwd === oldPwd) return new Response('Please enter a new Password!', { status: 400 });
                        await env.bpb.put('pwd', newPwd);
                        return new Response('Success', {
                            status: 200,
                            headers: {
                                'Set-Cookie': 'jwtToken=; Path=/; Secure; SameSite=None; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
                                'Content-Type': 'text/plain',
                            }
                        });

                    default:
                        // return new Response('Not found', { status: 404 });
                        url.hostname = 'www.speedtest.net';
                        url.protocol = 'https:';
                        request = new Request(url, request);
                        return await fetch(request);
                }
            } else {
                return url.pathname.startsWith('/tr') 
                    ? await trojanOverWSHandler(request, hashPassword, proxyIP)
                    : await vlessOverWSHandler(request, userID, dohURL, proxyIP);
            }
        } catch (err) {
            const errorPage = renderErrorPage('Something went wrong!', err, false, panelVersion);
            return new Response(errorPage, { status: 200, headers: {'Content-Type': 'text/html'}});
        }
    }
};
