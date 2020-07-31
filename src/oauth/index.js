const passport = require('passport');
const express = require('express');
const request = require('request');

const fs = require('fs');
const path = require('path');

const env = require('../data/env');
const { createIdentity } = require('../utils/identity');
const { log, logError, logRequest } = require('../utils/common');

const initializedProviders = [];

const oauthProviders = {
    facebook: {
        Strategy: require('passport-facebook').Strategy,
        requiredEnv: ['FACEBOOK_APP_ID', 'FACEBOOK_APP_SECRET'],
        options: {
            clientID: env.FACEBOOK_APP_ID,
            clientSecret: env.FACEBOOK_APP_SECRET,
            passReqToCallback: true,
        },
        scope: undefined,
        type: 'oauth',
    },
    google: {
        Strategy: require('passport-google-oauth').OAuth2Strategy,
        requiredEnv: ['GOOGLE_CONSUMER_KEY', 'GOOGLE_CONSUMER_SECRET'],
        options: {
            clientID: env.GOOGLE_CONSUMER_KEY,
            clientSecret: env.GOOGLE_CONSUMER_SECRET,
            passReqToCallback: true,
        },
        scope: ['profile'],
        type: 'oauth',
    },
    telegram: {
        Strategy: require('passport-telegram-official').TelegramStrategy,
        requiredEnv: ['TELEGRAM_BOT_TOKEN'],
        options: {
            botToken: env.TELEGRAM_BOT_TOKEN,
            passReqToCallback: true,
        },
        scope: undefined,
        type: 'oauth',
    },
    'google-token': {
        Strategy: require('passport-token-google2').Strategy,
        strategyName: 'google-token',
        requiredEnv: ['GOOGLE_CONSUMER_KEY', 'GOOGLE_CONSUMER_SECRET'],
        options: {
            clientID: env.GOOGLE_CONSUMER_KEY,
            clientSecret: env.GOOGLE_CONSUMER_SECRET,
            passReqToCallback: true,
        },
        scope: ['profile'],
        type: 'token',
    },
    'facebook-token': {
        Strategy: require('passport-facebook-token'),
        requiredEnv: ['FACEBOOK_APP_ID', 'FACEBOOK_APP_SECRET'],
        options: {
            clientID: env.FACEBOOK_APP_ID,
            clientSecret: env.FACEBOOK_APP_SECRET,
            passReqToCallback: true,
        },
        scope: ['profile'],
        type: 'token',
    },
    apple: {
        Strategy: require('passport-apple-token'),
        requiredEnv: ['APPLE_CLIENT_ID_WEB', 'APPLE_TEAM_ID', 'APPLE_KEY_ID', 'APLLE_PRIVATE_KEY'],
        options: {
            clientID: env.APPLE_CLIENT_ID_WEB,
            teamID: env.APPLE_TEAM_ID,
            keyID: env.APPLE_KEY_ID,
            key: fs.readFileSync(path.join(__dirname, `../../${env.APLLE_PRIVATE_KEY}`), 'utf-8'),
            passReqToCallback: true,
        },
        scope: undefined,
        type: 'oauth',
    },
    'apple-token': {
        Strategy: require('passport-apple-token'),
        requiredEnv: ['APPLE_CLIENT_ID_APP', 'APPLE_TEAM_ID', 'APPLE_KEY_ID', 'APLLE_PRIVATE_KEY'],
        options: {
            clientID: env.APPLE_CLIENT_ID_APP,
            teamID: env.APPLE_TEAM_ID,
            keyID: env.APPLE_KEY_ID,
            key: fs.readFileSync(path.join(__dirname, `../../${env.APLLE_PRIVATE_KEY}`), 'utf-8'),
            passReqToCallback: true,
        },
        scope: undefined,
        type: 'token',
    },
};

function validateEnv(envArray) {
    for (const envVar of envArray) {
        if (!env[envVar]) {
            logError(`${envVar} must be set`);
            return false;
        }
    }

    return true;
}

const buildRoutes = provider => ({
    route: `${env.AUTH_ROUTE_PREFIX}/${provider}`,
    callback: `${env.AUTH_ROUTE_PREFIX}/${provider}/callback`,
});

async function strategyCallback(req, accessToken, refreshToken, profile, done) {
    try {
        if (req.route.path === '/oauth/telegram') {
            [profile, done] = [accessToken, refreshToken];
            profile.provider = 'telegram';
        }

        if (!profile.provider) {
            profile.provider = 'apple';
        }

        const rawResult = await createIdentity(profile);

        if (rawResult.error) {
            logRequest(req, 'createIdentity result: ', rawResult.error);

            return done(null, rawResult.error);
        }

        logRequest(req, 'createIdentity result: ', rawResult.result);

        return done(null, rawResult.result);
    } catch (err) {
        logRequest(req, 'createIdentity', err);

        return done(err);
    }
}

function authenticateCallback(req, res) {
    const { user } = req;

    if (user.code && user.currentState) {
        res.cookie('commun_oauth_state', user.currentState);
        res.cookie('commun_oauth_identity', user.identity);
        res.cookie('commun_oauth_provider', user.provider);
    }

    if (user.code && user.code === 1101) {
        res.cookie('commun_oauth_state', 'registered');
    }

    if (user.success) {
        res.cookie('commun_oauth_identity', user.identity);
        res.cookie('commun_oauth_provider', user.provider);
    }

    return res.redirect('/');
}

function authenticateTokenCallback(req, res) {
    const { user } = req;

    if (user.code && user.currentState) {
        res.json({
            oauthState: user.currentState,
            identity: user.identity,
            provider: user.provider,
        });
    }

    if (user.code && user.code === 1101) {
        res.json({ oauthState: 'registered' });
    }

    if (user.success) {
        res.json({ identity: user.identity, provider: user.provider });
    }
}

passport.serializeUser((user, cb) => cb(null, user));
passport.deserializeUser((obj, cb) => cb(null, obj));

const oauth = app => {
    if (!env.GLS_REGISTRATION_CONNECT) {
        throw new Error('GLS_REGISTRATION_CONNECT env must not be empty');
    }

    app.use(passport.initialize());

    const providers = env.PROVIDERS;

    if (!providers) {
        throw new Error('PROVIDERS env must not be empty');
    }

    for (const provider of providers.split(',')) {
        const currentProvider = oauthProviders[provider];

        if (!currentProvider) {
            logError(`Unknown provider: ${provider}`);
            continue;
        }

        log(`Setting up provider: ${provider}`);

        const { Strategy, requiredEnv, options, scope, type } = currentProvider;

        if (!validateEnv(requiredEnv)) {
            logError(`${provider} is not initialized`);
            continue;
        }

        const { route, callback } = buildRoutes(provider);

        if (type === 'oauth') {
            passport.use(
                new Strategy(
                    { ...options, callbackURL: `${env.CALLBACK_AUTH_ROUTE_PREFIX}${callback}` },
                    strategyCallback
                )
            );

            if (provider === 'telegram') {
                app.get(route, passport.authenticate(provider), authenticateCallback);
            } else {
                app.get(route, passport.authenticate(provider, { scope }));
            }

            if (provider === 'apple') {
                app.post(
                    callback,
                    express.urlencoded(),
                    passport.authenticate(provider),
                    authenticateCallback
                );
            } else {
                app.get(
                    callback,
                    passport.authenticate(provider, { failureRedirect: env.FAILURE_REDIRECT_URL }),
                    authenticateCallback
                );
            }
        }

        if (type === 'token') {
            if (provider === 'apple-token') {
                passport.use(
                    provider,
                    new Strategy(
                        {
                            ...options,
                            callbackURL: `${env.CALLBACK_AUTH_ROUTE_PREFIX}${callback}`,
                        },
                        strategyCallback
                    )
                );

                app.post(
                    callback,
                    express.urlencoded(),
                    passport.authenticate(provider),
                    authenticateTokenCallback
                );
            } else {
                passport.use(provider, new Strategy({ ...options }, strategyCallback));

                app.get(
                    route,
                    passport.authenticate(provider, { scope }),
                    authenticateTokenCallback
                );
            }
        }

        initializedProviders.push(provider);
        log(`${provider} is initialized`);
    }

    if (!initializedProviders.length) {
        throw new Error('providers are not initialized');
    }

    app.get('/oauth/apple-token', (req, res) => {
        request.post(
            {
                url: `${env.CALLBACK_AUTH_ROUTE_PREFIX}/oauth/apple-token/callback`,
                form: {
                    code: req.query.access_token,
                },
            },
            (err, response, body) => {
                if (err) {
                    res.status(401).json({ status: 'false' });
                }

                res.set('Content-Type', 'application/json');
                res.send(body);
            }
        );
    });

    app.get(env.SUCCESS_REDIRECT_URL, (req, res) => {
        res.json({ status: 'ok' });
    });

    app.get(env.FAILURE_REDIRECT_URL, (req, res) => {
        res.status(401).json({ status: 'false' });
    });
};

module.exports = oauth;
