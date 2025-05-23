import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import { connectDB } from './config/db';
import router from './routes/router';
import { config } from './config/test-config';
import cookieParser from 'cookie-parser';

const app = express();
const port = config.PORT

connectDB();
app.use(express.static('public'));
app.use(express.static(path.join(__dirname, "ts")));
app.set('views', path.join(__dirname, 'views'));
app.use(cookieParser());

app.set('view engine', 'ejs');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/', router);


app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});