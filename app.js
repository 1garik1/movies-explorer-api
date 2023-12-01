require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const { errors } = require('celebrate');
const errorHandler = require('./middlewares/errorHandler');
const { requestLogger, errorLogger } = require('./middlewares/logger');

const routes = require('./routes');

const { PORT = 3000 } = process.env;
const app = express();
app.use(requestLogger);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(cors);

app.get('/crash-test', () => {
  setTimeout(() => {
    throw new Error('Сервер сейчас упадёт');
  }, 0);
});

app.use('/', routes);

app.use(errorLogger);

app.use(errors());
app.use(errorHandler);

mongoose.connect('mongodb://localhost:27017/bitfilmsdb');

app.listen(PORT);
