require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');

const helmet = require('helmet');
const bodyParser = require('body-parser');
const cors = require('cors');
const { errors } = require('celebrate');
const { limiterConfig } = require('./config/rateLimiter');
const errorHandler = require('./middlewares/errorHandler');
const { requestLogger, errorLogger } = require('./middlewares/logger');
const routes = require('./routes');

mongoose.set('strictQuery', true);
const { PORT = 3000 } = process.env;
const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(cors());

app.get('/crash-test', () => {
  setTimeout(() => {
    throw new Error('Сервер сейчас упадёт');
  }, 0);
});

app.use(requestLogger);
app.use(limiterConfig);
app.use(helmet());
app.use('/', routes);

app.use(errorLogger);

app.use(errors());
app.use(errorHandler);
mongoose.connect('mongodb://127.0.0.1:27017/bitfilmsdb');

app.listen(PORT);
