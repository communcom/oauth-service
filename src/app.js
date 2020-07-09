require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const morgan = require('morgan');

const env = require('./data/env');
const oauth = require('./oauth');
const { log, logRequest } = require('./utils/common');

const morganConfig =
    ':date[iso] :req[cf-ray] :method :url :status :res[content-length] - :response-time ms';

const host = env.GLS_CONNECTOR_HOST;
const port = env.GLS_CONNECTOR_PORT;
const app = express();

app.use(morgan(morganConfig));

app.use(bodyParser.json());
app.use(
    bodyParser.urlencoded({
        extended: true,
    })
);

oauth(app);

app.use((err, req, res, next) => {
    logRequest(req, err);
    res.status(500).json({ status: 'false' });
});

app.listen({ host, port }, err => {
    if (err) {
        log(err);
        process.exit(1);
    }

    log('app running on port:', port);
});
