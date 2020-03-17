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

async function getNewPemCert(domainName) {
    let legoCode = await runLegoClient(zoneApiToken, dnsApiToken, domainName);
    console.log('lego return :', legoCode);
    return legoCode;
}

async function getPfxCert(zoneApiToken, dnsApiToken, domainName) {
    let pemPath = path.resolve(__dirname, '.lego', 'certificates', '_.' + domainName + '.pem');
    if (domainName && false) {
        let legoRes = await getNewPemCert(zoneApiToken, dnsApiToken, domainName);
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

function runLegoClient(zoneApiToken, dnsApiToken, domainName) {
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

function canUseWildCharCert(name, domainName) {
    return name.toLowerCase() === domainName.toLowerCase() || name.toLowerCase().endsWith('.' + domainName.toLowerCase());
}

async function tryRenewCertForSite(domainName) {
    let credentials = new identity.ChainedTokenCredential(new identity.DefaultAzureCredential());
    const secretClient = new KeyVaultSecret.SecretClient(KEY_VAULT_URL, credentials);
    const certClient = new CertificateClient(KEY_VAULT_URL, credentials);

    const configEntrySecret = await secretClient.getSecret(CONFIG_INDEX);
    console.info(`CONFIG_INDEX value is: ${configEntrySecret.value}.`);
    const configEntry = configEntrySecret.value.split(',');
    const zoneApiToken = (await secretClient.getSecret(configEntry[0])).value;
    const dnsApiToken = (await secretClient.getSecret(configEntry[1])).value;

    const siteCert = await getWebSiteAndCerts(domainName);
    const targetSite = siteCert.targetSite;
    const targetCertList = siteCert.certList.filter(c => c.hostNames.some(hn => hn.toLowerCase() === '*.' + domainName.toLowerCase())).sort((a, b) => b.expirationDate.getTime() - a.expirationDate.getTime());
    let targetThumbprint = '';
    let needRenew = false;
    if (targetCertList.length > 0) {
        targetThumbprint = targetCertList[0].thumbprint;
        const expireTime = targetCertList[0].expirationDate.getTime();
        const renewTime = new Date().getTime() + 86400 * 1000 * 35;
        if (expireTime < renewTime) {
            needRenew = true;
        }
    } else {
        needRenew = true;
    }

    // renew if needed
    if (needRenew || FORCE_RENEW === 'true') {
        const pfxInfo = await getPfxCert(zoneApiToken, dnsApiToken, domainName);
        const uploadRes = await uploadCertToSite(domainName, targetSite.location, pfxInfo.certBytes, pfxInfo.pfxPW);
        targetThumbprint = uploadRes.thumbprint;
        // save a copy to keyvault just in case
        await certClient.importCertificate(configEntry[2], pfxInfo.certBytes, {
            password: pfxInfo.pfxPW,
            policy: {
                keySize: 2048,
                keyType: 'RSA',
                reuseKey: false
            }
        });
    }

    const siteClient = await getWebSiteClient();
    for (let i = 0; i < targetSite.hostNameSslStates.length; i++) {
        let sslState = targetSite.hostNameSslStates[i];
        if (canUseWildCharCert(sslState.name, domainName)) {
            if (sslState.thumbprint !== targetThumbprint) {
                sslState.thumbprint = targetThumbprint;
                sslState.toUpdate = true;
                sslState.sslState = 'SniEnabled';
                const sslRes = await siteClient.webApps.createOrUpdateHostNameBinding(targetSite.resourceGroup, targetSite.name, sslState.name, sslState);
            }
        }
    }

    // clean up expired certs
    for (let i = 1; i < targetCertList.length; i++) {
        const expireTime = targetCertList[i].expirationDate.getTime();
        const removeTime = new Date().getTime();
        if (expireTime < removeTime) {
            await siteClient.certificates.deleteMethod(targetSite.resourceGroup, targetCertList[i].name);
        }
    }
}

try {
    tryRenewCertForSite(DOMAIN_NAME);
}
catch (err) {
    console.error(err);
    process.exit(1);
}