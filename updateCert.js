const child_process = require('child_process');
const crypto = require('crypto')
const path = require('path');
const fs = require('fs');
const KeyVaultSecret = require('@azure/keyvault-secrets');
const { CertificateClient } = require("@azure/keyvault-certificates");
const identity = require('@azure/identity');

const msRestNodeAuth = require("@azure/ms-rest-nodeauth");
const { WebSiteManagementClient } = require("@azure/arm-appservice");

const KEY_VAULT_URL = process.env['KEY_VAULT_URL'];
const CONFIG_INDEX = process.env['CONFIG_INDEX'];
const FORCE_RENEW = process.env['FORCE_RENEW'];
const DOMAIN_NAME = process.env['DOMAIN_NAME'];
const EMAIL_NAME = process.env['EMAIL_NAME'];
const DNS_PROVIDER = process.env['DNS_PROVIDER'];

const AZURE_CLIENT_ID = process.env['AZURE_CLIENT_ID'];
const AZURE_TENANT_ID = process.env['AZURE_TENANT_ID'];
const AZURE_CLIENT_SECRET = process.env['AZURE_CLIENT_SECRET'];
const AZURE_SUBSCRIPTION_ID = process.env['AZURE_SUBSCRIPTION_ID'];
const SITE_RESOURCE_GROUP = process.env['SITE_RESOURCE_GROUP'];

async function getWebSiteClient() {
    let creds;
    if (AZURE_CLIENT_SECRET) {
        creds = await msRestNodeAuth.loginWithServicePrincipalSecret(AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID);
    } else {
        creds = await msRestNodeAuth.loginWithVmMSI();
    }
    return new WebSiteManagementClient(creds, AZURE_SUBSCRIPTION_ID);
}

async function getWebSiteAndCerts(domainName) {
    const siteClient = await getWebSiteClient();
    const appList = await siteClient.webApps.listByResourceGroup(SITE_RESOURCE_GROUP);
    const targetSite = appList.find(s => s.hostNames.some(hn => hn.toLowerCase() === domainName.toLowerCase()));
    if (!targetSite) {
        console.error('cannot find site with hostName', DOMAIN_NAME);
        throw 'cannot find site ' + DOMAIN_NAME;
        // targetSite = appList.find(s => true);
    }
    const certList = await siteClient.certificates.listByResourceGroup(SITE_RESOURCE_GROUP);
    return { targetSite, certList };
}

async function uploadCertToSite(domainName, location, pfxBlob, pfxPW) {
    const siteClient = await getWebSiteClient();
    const certName = domainName + '-' + crypto.randomBytes(8).toString('base64');
    const updateRes = await siteClient.certificates.createOrUpdate(SITE_RESOURCE_GROUP, certName, {
        pfxBlob,
        password: pfxPW,
        location
    });
    return updateRes;
}

async function getNewPemCertCloudFlare(zoneApiToken, dnsApiToken, domainName) {
    let legoCode = await runLegoCloudFlareClient(zoneApiToken, dnsApiToken, domainName);
    console.log('lego return :', legoCode);
    return legoCode;
}

async function getNewPemCertGodaddy(dnsApiKey, dnsApiSec, domainName) {
    let legoCode = await runLegoGodaddyClient(dnsApiKey, dnsApiSec, domainName);
    console.log('lego return :', legoCode);
    return legoCode;
}

async function getNewPemCert(configEntryZero, configEntryOne, domainName) {
    if (DNS_PROVIDER === 'Godaddy') {
        let legoRes = await getNewPemCertGodaddy(configEntryZero, configEntryOne, domainName);
        return legoRes;
    } else {
        let legoRes = await getNewPemCertCloudFlare(configEntryZero, configEntryOne, domainName);
        return legoRes;
    }
}

// config pass configEntry as array or something
async function getPfxCert(configEntryZero, configEntryOne, domainName) {
    let pemPath = path.resolve(__dirname, '.lego', 'certificates', '_.' + domainName + '.pem');
    if (domainName) {
        let legoRes = await getNewPemCert(configEntryZero, configEntryOne, domainName);
        pemPath = legoRes.legoPemPath;
    }

    const pfxPath = pemPath.replace('.pem', '.pfx');
    const rndPath = pemPath.replace('.pem', '.rnd');
    if (fs.existsSync(pfxPath)) {
        fs.unlinkSync(pfxPath);
    }
    if (fs.existsSync(rndPath)) {
        fs.unlinkSync(rndPath);
    }

    const pfxPW = crypto.randomBytes(8).toString('base64');
    // console.log('pfxPW is ', pfxPW);
    let openSSLRes = child_process.spawnSync('openssl', [
        'pkcs12',
        '-export',
        '-out',
        pfxPath,
        '-inkey',
        pemPath,
        '-in',
        pemPath,
        '-passout',
        'env:EWA_PFX_PW'
    ], {
        env: {
            RANDFILE: rndPath,
            EWA_PFX_PW: pfxPW,
        }
    });
    console.log(openSSLRes.stdout.toString('utf8'));
    console.error(openSSLRes.stderr.toString('utf8'));
    let certBytes = fs.readFileSync(pfxPath);

    return { certBytes, pfxPW };
}

function runLegoCloudFlareClient(zoneApiToken, dnsApiToken, domainName) {
    let legoExe = path.resolve(__dirname, 'lego');
    let legoDataPath = path.resolve(__dirname, '.lego');
    let legoPemPath = path.resolve(legoDataPath, 'certificates', '_.' + domainName + '.pem');
    let legoProc = child_process.spawn(legoExe, [
        // '--server=https://acme-staging-v02.api.letsencrypt.org/directory',
        '-a',
        '--pem',
        '-k',
        'rsa2048',
        '--path',
        legoDataPath,
        '-d',
        '*.' + domainName,
        '-d',
        domainName,
        '--dns',
        'cloudflare',
        '--email',
        EMAIL_NAME,
        'run'
    ], {
        env: {
            CF_ZONE_API_TOKEN: zoneApiToken,
            CF_DNS_API_TOKEN: dnsApiToken
        }
    });

    legoProc.stderr.on('data', (data) => {
        console.error(`lego stderr: ${data}`);
    });

    legoProc.stdout.on('data', (data) => {
        console.log(`lego stdout: ${data}`);
    });

    legoProc.on('error', (err) => {
        console.error('Failed to start lego process.', err);
    });

    return new Promise((resolve, reject) => {
        legoProc.on('close', (code) => {
            console.log(`lego process exited with code ${code}`);
            resolve({ code, legoPemPath });
        });
    });
}

function runLegoGodaddyClient(dnsApiKey, dnsApiSec, domainName) {
    let legoExe = path.resolve(__dirname, 'lego');
    let legoDataPath = path.resolve(__dirname, '.lego');
    let legoPemPath = path.resolve(legoDataPath, 'certificates', '_.' + domainName + '.pem');
    let legoProc = child_process.spawn(legoExe, [
        // '--server=https://acme-staging-v02.api.letsencrypt.org/directory',
        '-a',
        '--pem',
        '-k',
        'rsa2048',
        '--path',
        legoDataPath,
        '-d',
        '*.' + domainName,
        '-d',
        domainName,
        '--dns',
        'godaddy',
        '--email',
        EMAIL_NAME,
        'run'
    ], {
        env: {
            GODADDY_API_KEY: dnsApiKey,
            GODADDY_API_SECRET: dnsApiSec
        }
    });

    legoProc.stderr.on('data', (data) => {
        console.error(`lego stderr: ${data}`);
    });

    legoProc.stdout.on('data', (data) => {
        console.log(`lego stdout: ${data}`);
    });

    legoProc.on('error', (err) => {
        console.error('Failed to start lego process.', err);
    });

    return new Promise((resolve, reject) => {
        legoProc.on('close', (code) => {
            console.log(`lego process exited with code ${code}`);
            resolve({ code, legoPemPath });
        });
    });
}

function canUseWildCharCert(name, domainName) {
    return name.toLowerCase() === domainName.toLowerCase() || name.toLowerCase().endsWith('.' + domainName.toLowerCase());
}

async function tryRenewCertForSite(domainName) {
    const siteCert = await getWebSiteAndCerts(domainName);
    const targetSite = siteCert.targetSite;
    const targetCertList = siteCert.certList.filter(c => c.hostNames.some(hn => hn.toLowerCase() === '*.' + domainName.toLowerCase())).sort((a, b) => b.expirationDate.getTime() - a.expirationDate.getTime());
    let targetThumbprint = '';
    let needRenew = false;
    if (targetCertList.length > 0) {
        targetThumbprint = targetCertList[0].thumbprint;
        const expireTime = targetCertList[0].expirationDate.getTime();
        const renewTime = new Date().getTime() + 86400 * 1000 * 35;
        console.log(`latest cert expiring at ${expireTime} V.S. renewThreshold ${renewTime}`);
        if (expireTime < renewTime) {
            needRenew = true;
        }
    } else {
        needRenew = true;
    }

    // renew if needed
    if (needRenew || FORCE_RENEW === 'true') {
        let credentials = new identity.ChainedTokenCredential(new identity.DefaultAzureCredential(), new identity.ManagedIdentityCredential());
        const secretClient = new KeyVaultSecret.SecretClient(KEY_VAULT_URL, credentials);
        const certClient = new CertificateClient(KEY_VAULT_URL, credentials);
    
        const configEntrySecret = await secretClient.getSecret(CONFIG_INDEX);
        console.log(`CONFIG_INDEX value is: ${configEntrySecret.value}.`);
        const configEntry = configEntrySecret.value.split(',');

        // should 
        const configEntry0 = (await secretClient.getSecret(configEntry[0])).value;
        const configEntry1 = (await secretClient.getSecret(configEntry[1])).value;

        console.log(`getting cert from lets encrypt`);
        const pfxInfo = await getPfxCert(configEntry0, configEntry1, domainName);
        console.log(`uploading cert to website`);
        const uploadRes = await uploadCertToSite(domainName, targetSite.location, pfxInfo.certBytes, pfxInfo.pfxPW);
        targetThumbprint = uploadRes.thumbprint;
        console.log(`new cert uploaded with thumbprint ${targetThumbprint}`);
        // save a copy to keyvault just in case
        await certClient.importCertificate(configEntry[2], pfxInfo.certBytes, {
            password: pfxInfo.pfxPW,
            policy: {
                keySize: 2048,
                keyType: 'RSA',
                reuseKey: false
            }
        });
        console.log(`new cert saved to keyvault under ${configEntry[2]}`);
    } else {
        console.log(`not renew uploaded certs`);
    }

    console.log(`checking if site cert need update`);
    const siteClient = await getWebSiteClient();
    for (let i = 0; i < targetSite.hostNameSslStates.length; i++) {
        let sslState = targetSite.hostNameSslStates[i];
        console.log(`checking ${sslState.name}`);
        if (canUseWildCharCert(sslState.name, domainName)) {
            console.log(`${sslState.name} can use cert for ${domainName}`);
            if (sslState.thumbprint !== targetThumbprint) {
                console.log(`updating ${sslState.name} cert thumbprint ${sslState.thumbprint} to use cert thumbprint ${targetThumbprint}`);
                sslState.thumbprint = targetThumbprint;
                sslState.toUpdate = true;
                sslState.sslState = 'SniEnabled';
                const sslRes = await siteClient.webApps.createOrUpdateHostNameBinding(targetSite.resourceGroup, targetSite.name, sslState.name, sslState);
                console.log(`${sslState.name} updated with ${sslRes.sslState}`);
            } else {
                console.log(`${sslState.name} already use cert ${targetThumbprint}`);
            }
        }
    }

    // clean up expired certs
    console.log(`clean up expired certs`);
    for (let i = 1; i < targetCertList.length; i++) {
        const expireTime = targetCertList[i].expirationDate.getTime();
        const removeTime = new Date().getTime();
        console.log(`${targetCertList[i].name} expireTime ${expireTime} V.S. removeTime ${removeTime}`);
        if (expireTime < removeTime) {
            await siteClient.certificates.deleteMethod(targetSite.resourceGroup, targetCertList[i].name);
            console.log(`${targetCertList[i].name} expireTime ${expireTime} removed`);
        }
    }

    // clean up old certs
    console.log(`clean up old certs`);
    let siteName2thumbprintDict = {};
    for (let i = 0; i < targetSite.hostNameSslStates.length; i++) {
        let sslState = targetSite.hostNameSslStates[i];
        // console.log(`checking ${sslState.name}`);
        if (sslState && sslState.thumbprint && sslState.name) {
            siteName2thumbprintDict[sslState.name] = sslState.thumbprint;
        }
    }
    let cert2ExpirationDict = {};
    siteCert.certList.forEach((cert) => {
        if (cert.hostNames && cert.hostNames.length && cert.thumbprint && cert.expirationDate) {
            let hostSorted = getCertNamesKey(cert.hostNames);
            if (!cert2ExpirationDict[hostSorted] || cert2ExpirationDict[hostSorted] < cert.expirationDate.getTime()) {
                cert2ExpirationDict[hostSorted] = cert.expirationDate.getTime();
            }
        }
    });

    for (let i = 0; i < siteCert.certList.length; i ++) {
        let cert = siteCert.certList[i];
        if (cert.hostNames && cert.hostNames.length && cert.thumbprint && cert.expirationDate) {
            let hostSorted = getCertNamesKey(cert.hostNames);
            if (cert.expirationDate.getTime() < cert2ExpirationDict[hostSorted]) {
                console.log(`old cert ${hostSorted} ${cert.expirationDate} ${cert.thumbprint} can be removed as there is newer cert`);
                let notInUse = true;
                cert.hostNames.forEach((hostName) => {
                    if (siteName2thumbprintDict[hostName] && siteName2thumbprintDict[hostName] === cert.thumbprint) {
                        notInUse = false;
                    }
                });
                if (notInUse) {
                    console.log(`removing old cert ${hostSorted} ${cert.expirationDate} ${cert.thumbprint}`);
                    try {
                        await siteClient.certificates.deleteMethod(targetSite.resourceGroup, cert.name);
                    }
                    catch (err) {
                        console.error(`failed to remove old cert ${hostSorted} ${cert.expirationDate} ${cert.thumbprint}`, err);
                    }
                } else {
                    console.log(`old cert ${hostSorted} ${cert.thumbprint} still in use`);
                }
            }
        }
    };
    console.log(`all done`);
}

function getCertNamesKey(hostNames) {
    return hostNames.sort().join(',');
}

try {
    console.log('begin to refreshing', DOMAIN_NAME);
    tryRenewCertForSite(DOMAIN_NAME);
}
catch (err) {
    console.error(err);
    process.exit(1);
}