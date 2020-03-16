require('dotenv').config();
const express = require('express');

const env = require('./data/env');
const oauth = require('./oauth');

const host = env.GLS_CONNECTOR_HOST;
const port = env.GLS_CONNECTOR_PORT;
const app = express();

oauth(app);

app.listen({ host, port }, err => {
    if (err) {
        console.error(err);
        process.exit(1);
    }

    console.log('app running on port:', port);
});
