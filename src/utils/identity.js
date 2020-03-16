const request = require('request-promise-native');

const env = require('../data/env');

async function createIdentity(profile) {
    const { id, provider } = profile;

    try {
        const result = await request({
            method: 'POST',
            uri: env.GLS_REGISTRATION_CONNECT,
            body: JSON.stringify({
                jsonrpc: '2.0',
                id: 1,
                method: 'createIdentity',
                params: {
                    identity: id,
                    provider,
                    secureKey: env.GLS_OAUTH_SECURE_KEY,
                },
            }),
            json: true,
        });

        return result;
    } catch (err) {
        throw err;
    }
}

module.exports = {
    createIdentity,
};
