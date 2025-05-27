const jwt = require('jsonwebtoken');
import { config } from '../config/test-config';
import User from '../models/AuthModels';
import { Request, Response, NextFunction } from 'express';

export interface AuthenticatedRequest extends Request {
    user?: any;
    token?: string;
}


export const auth = async (req: any, res: Response, next: NextFunction) => {
    try {
        const token = req.cookies.utoken;
        const decoded: any = jwt.verify(token, config.JWT_SECRET);
        const user = await User.findOne({ _id: decoded._id, 'tokens.token': token });

        if (!user) throw new Error();

        req.token = token;
        req.user = user;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Unauthorized' });
    }
};