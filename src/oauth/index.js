const passport = require('passport');

const env = require('../data/env');
const { createIdentity } = require('../utils/identity');

const initializedProviders = [];

const oauthProviders = {
    facebook: {
        Strategy: require('passport-facebook').Strategy,
        requiredEnv: ['FACEBOOK_APP_ID', 'FACEBOOK_APP_SECRET'],
        options: {
            clientID: env.FACEBOOK_APP_ID,
            clientSecret: env.FACEBOOK_APP_SECRET,
        },
    },
    google: {
        Strategy: require('passport-google-oauth').OAuth2Strategy,
        requiredEnv: ['GOOGLE_CONSUMER_KEY', 'GOOGLE_CONSUMER_SECRET'],
        options: {
            consumerKey: env.GOOGLE_CONSUMER_KEY,
            consumerSecret: env.GOOGLE_CONSUMER_SECRET,
        },
    },
    twitter: {
        Strategy: require('passport-twitter').Strategy,
        requiredEnv: ['TWITTER_CONSUMER_KEY', 'TWITTER_CONSUMER_SECRET'],
        options: {
            consumerKey: env.TWITTER_CONSUMER_KEY,
            consumerSecret: env.TWITTER_CONSUMER_SECRET,
        },
    },
    /* TODO
    apple: {
        Strategy: require('passport-appleid'),
        requiredEnv: [
            'APPLE_SERVICE_ID',
            'APPLE_TEAM_ID',
            'APPLE_KEY_IDENTIFIER',
            'APLLE_PRIVATE_KEY',
        ],
        options: {
            clientID: env.APPLE_SERVICE_ID,
            teamId: env.APPLE_TEAM_ID,
            keyIdentifier: env.APPLE_KEY_IDENTIFIER,
            privateKeyPath: env.APLLE_PRIVATE_KEY,
        },
    }, */
};

function validateEnv(envArray) {
    for (const envVar of envArray) {
        if (!env[envVar]) {
            console.error(`ERROR - ${envVar} must be set`);
            return false;
        }
    }

    return true;
}

const buildRoutes = provider => ({
    route: `${env.AUTH_ROUTE_PREFIX}/${provider}`,
    callback: `${env.AUTH_ROUTE_PREFIX}/${provider}/callback`,
});

async function strategyCallback(accessToken, refreshToken, profile, done) {
    try {
        const rawResult = await createIdentity(profile);

        if (rawResult.error) {
            return done(null, rawResult.error);
        }

        return done(null, rawResult.result);
    } catch (err) {
        console.error(err);

        return done(err);
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
            console.log(`ERROR - Unknown provider: ${provider}`);
            continue;
        }

        console.log(`Setting up provider: ${provider}`);

        const { Strategy, requiredEnv, options } = currentProvider;

        if (!validateEnv(requiredEnv)) {
            console.log(`ERROR - ${provider} is not initialized`);
            continue;
        }

        const { route, callback } = buildRoutes(provider);

        passport.use(new Strategy({ ...options, callbackURL: callback }, strategyCallback));

        app.get(route, passport.authenticate(provider));

        app.get(
            callback,
            passport.authenticate(provider, { failureRedirect: env.FAILURE_REDIRECT_URL }),
            (req, res) => {
                const { user } = req;

                if (user.code && user.currentState) {
                    res.cookie('commun_oauth_error', user.currentState);
                }

                if (user.code && user.code === 1101) {
                    res.cookie('commun_oauth_error', 'registered');
                }

                if (user.success) {
                    res.cookie('commun_oauth_identity', user.identity);
                    res.cookie('commun_oauth_provider', user.provider);
                }

                return res.redirect('/');
            }
        );

        initializedProviders.push(provider);
        console.log(`${provider} is initialized`);
    }

    if (!initializedProviders.length) {
        throw new Error('providers are not initialized');
    }

    app.get(env.SUCCESS_REDIRECT_URL, (req, res) => {
        res.json({ status: 'ok' });
    });

    app.get(env.FAILURE_REDIRECT_URL, (req, res) => {
        res.status(401).json({ status: 'false' });
    });
};

module.exports = oauth;
