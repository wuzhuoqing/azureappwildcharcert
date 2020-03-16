const child_process = require('child_process');
const crypto = require('crypto')
const path = require('path');
const fs = require('fs');
const KeyVaultSecret = require('@azure/keyvault-secrets');
const { CertificateClient } = require("@azure/keyvault-certificates");
const identity = require('@azure/identity');
const KEY_VAULT_URL = process.env['KEY_VAULT_URL'];
const CONFIG_INDEX = process.env['CONFIG_INDEX'];
const FORCE_RENEW = process.env['FORCE_RENEW'];
const DOMAIN_NAME = process.env['DOMAIN_NAME'];
const EMAIL_NAME = process.env['EMAIL_NAME'];

function getKeyVaultCredentials() {
    return new identity.ChainedTokenCredential(new identity.DefaultAzureCredential());
}

let credentials = getKeyVaultCredentials();
const secretClient = new KeyVaultSecret.SecretClient(KEY_VAULT_URL, credentials);
const certClient = new CertificateClient(KEY_VAULT_URL, credentials);

async function uploadCert(domainName, certName) {
    pemPath = path.resolve(__dirname, '.lego', 'certificates', '_.' + domainName + '.pem');
    pfxPath = path.resolve(__dirname, '.lego', 'certificates', '_.' + domainName + '.pfx');
    rndPath = path.resolve(__dirname, '.lego', 'certificates', '_.' + domainName + '.rnd');
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
    return await certClient.importCertificate(certName, certBytes, {
        password: pfxPW,
        policy: {
            keySize: 2048,
            keyType: 'RSA',
            reuseKey: false
        } 
    });
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

async function main() {
    const uploadRes = await uploadCert(DOMAIN_NAME, 'EWA-WEB-CERT');
    console.log(uploadRes);

    const configEntrySecret = await secretClient.getSecret(CONFIG_INDEX);
    console.info(`Your secret value is: ${configEntrySecret.value}.`);
    const configEntry = configEntrySecret.value.split(',');
    let needRenew = false;
    if (FORCE_RENEW !== 'true') {
        try {
            const webCertificate = await certClient.getCertificate(configEntry[2]);
            const expireTime = webCertificate.properties.expiresOn.getTime();
            const renewTime = new Date().getTime() + 86400 * 1000 * 35;
            if (expireTime < renewTime) {
                needRenew = true;
            }
        }
        catch (err) {
            console.error(err);
            if (err.code && err.code === 'CertificateNotFound') {
                needRenew = true;
            }
        }
    } else {
        needRenew = true;
    }
    if (needRenew) {
        const zoneApiSec = await secretClient.getSecret(configEntry[0]);
        let zoneApiToken = zoneApiSec.value;
        const dnsApiSec = await secretClient.getSecret(configEntry[1]);
        let dnsApiToken = dnsApiSec.value;
        let legoCode = await runLegoClient(zoneApiToken, dnsApiToken, DOMAIN_NAME);
        console.log('lego return :', legoCode);

        const uploadRes = await uploadCert(DOMAIN_NAME, configEntry[2]);
        console.log(uploadRes);            
    }
}

try {
    main();
}
catch (err) {
    console.error(err);
    process.exit(1);
    // some changes
}